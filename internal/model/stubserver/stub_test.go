package stubserver

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

const fixturePath = "../../testdata/transcripts/basic.json"

func readFixture() ([]byte, error) { return os.ReadFile(fixturePath) }

// post sends a chat request to the stub and returns the response and body.
func post(t *testing.T, s *Server, path, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(b)
}

// TestLoadTranscriptRejectsBadVersion pins the versioned-fixture contract.
func TestLoadTranscriptRejectsBadVersion(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"wrong version", `{"version":"styx.transcript/v2","turns":[{"response":{}}]}`},
		{"missing version", `{"turns":[{"response":{}}]}`},
		{"no turns", `{"version":"styx.transcript/v1","turns":[]}`},
		{"not json", `{`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadTranscript([]byte(tt.data)); err == nil {
				t.Fatal("LoadTranscript() = nil error, want rejection")
			}
		})
	}
}

// TestReplayServesTranscriptFixture is the replay acceptance at the wire
// level: the versioned fixture streams through the stub as SSE.
func TestReplayServesTranscriptFixture(t *testing.T) {
	data, err := readFixture()
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	tr, err := LoadTranscript(data)
	if err != nil {
		t.Fatalf("LoadTranscript() error = %v", err)
	}
	s := Replay(tr)
	defer s.Close()

	// /models advertises the transcript's model, so client startup passes.
	resp, err := s.Client().Get(s.URL() + "/models")
	if err != nil {
		t.Fatalf("GET /models: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), tr.Model) {
		t.Errorf("/models = %s, want it to contain %q", body, tr.Model)
	}

	_, stream := post(t, s, "/chat/completions",
		`{"model":"deepseek-flash","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	// Arguments stream in fragments, so assert the call identity and cache
	// fields rather than a contiguous argument string.
	for _, want := range []string{"reasoning_content", "tool_calls", `"name":"read_file"`, "prompt_cache_hit_tokens", "[DONE]"} {
		if !strings.Contains(stream, want) {
			t.Errorf("replayed stream missing %q:\n%s", want, stream)
		}
	}
}

// TestStrictEnforcement rejects a scripted tool call that does not conform to
// strict mode, mirroring a strict-mode provider.
func TestStrictEnforcement(t *testing.T) {
	s := New(
		WithStrictEnforcement(true),
		WithScript(Turn{ToolCalls: []ScriptedToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":`}}}),
	)
	defer s.Close()

	tools := `[{"type":"function","function":{"name":"read_file","strict":true,"parameters":{"type":"object"}}}]`

	// Non-JSON arguments for a strict tool are rejected.
	resp, body := post(t, s, "/chat/completions",
		`{"model":"deepseek-flash","stream":true,"tools":`+tools+`,"messages":[]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(body, "not valid JSON") {
		t.Errorf("body = %s, want a strict-mode violation", body)
	}

	// A tool that is not declared strict is rejected too.
	s2 := New(
		WithStrictEnforcement(true),
		WithScript(Turn{ToolCalls: []ScriptedToolCall{{ID: "c1", Name: "bash", Arguments: `{}`}}}),
	)
	defer s2.Close()
	resp, body = post(t, s2, "/chat/completions",
		`{"model":"deepseek-flash","stream":true,"tools":`+tools+`,"messages":[]}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not declared") {
		t.Errorf("status/body = %d / %s, want 400 about a non-strict tool", resp.StatusCode, body)
	}
}

// TestBetaEndpoint pins that the strict endpoint path is served.
func TestBetaEndpoint(t *testing.T) {
	s := New(WithScript(Text("ok")))
	defer s.Close()
	_, body := post(t, s, "/beta/chat/completions", `{"model":"deepseek-flash","stream":true,"messages":[]}`)
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("beta stream = %s, want a completed stream", body)
	}
}

// TestFaultTurn checks the injected HTTP status.
func TestFaultTurn(t *testing.T) {
	s := New(WithScript(FaultStatus(429)))
	defer s.Close()
	resp, body := post(t, s, "/chat/completions", `{"model":"deepseek-flash","stream":true,"messages":[]}`)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", resp.StatusCode)
	}
	if !strings.Contains(body, "rate_limit_error") {
		t.Errorf("body = %s, want a rate-limit error object", body)
	}
}
