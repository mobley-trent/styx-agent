package agent

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/engagement"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// engagementAt parses a synthetic engagement file with the loader clock pinned,
// so expiry never interferes with a loop test.
func engagementAt(t *testing.T, src string, now time.Time) *engagement.Engagement {
	t.Helper()
	eng, err := engagement.Parse(context.Background(), []byte(src),
		engagement.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("parse engagement: %v", err)
	}
	return eng
}

// scopeFile is a minimal IP-only engagement: no DNS, so loop tests stay
// hermetic. The caller varies the ROE flags.
const scopeFile = `apiVersion: styx.engagement/v1
name: loop-test
operator: eddy
targets:
  - 192.0.2.44
roe:
  exploit_allowed: EXPLOIT
  destructive_forbidden: DESTRUCTIVE
`

func scopeSource(exploit, destructive bool) string {
	src := strings.Replace(scopeFile, "EXPLOIT", boolString(exploit), 1)
	return strings.Replace(src, "DESTRUCTIVE", boolString(destructive), 1)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func loopClock(t *testing.T, at string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestLoopInScopeNetworkAutoAllowsAndAudits(t *testing.T) {
	now := loopClock(t, "2026-09-29T12:00:00Z")
	eng := engagementAt(t, scopeSource(true, true), now)
	fetcher := &recordingFetcher{body: "in-scope body"}
	var auditBuf bytes.Buffer
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "web_fetch", `{"url":"http://192.0.2.44/status"}`)),
		fakemodel.Text("fetched"),
	))
	engine := mustEngine(t, policy.ModeEngagement,
		policy.WithScope(eng.Scope()), policy.WithROE(eng.ROE()), policy.WithClock(func() time.Time { return now }))
	loop := NewLoop(fake, mustRegistry(t, WebFetchTool(fetcher)), engine,
		audit.NewWriter(&auditBuf), testSystemPrompt)

	if _, err := loop.Run(context.Background(), nil, "fetch it"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(fetcher.urls) != 1 {
		t.Fatalf("fetcher ran %d times, want the in-scope fetch to execute without a prompt", len(fetcher.urls))
	}
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Verdict != audit.VerdictAllow || records[0].Reason != string(policy.ReasonInScope) {
		t.Fatalf("audit records = %+v, want one allow/in-scope entry", records)
	}
	if records[0].Mode != audit.ModeEngagement {
		t.Errorf("audit mode = %q, want engagement", records[0].Mode)
	}
}

func TestLoopOutOfScopeNetworkPrompts(t *testing.T) {
	now := loopClock(t, "2026-09-29T12:00:00Z")
	eng := engagementAt(t, scopeSource(true, true), now)
	fetcher := &recordingFetcher{body: "outside body"}
	prompter := &scriptedPrompter{}
	var auditBuf bytes.Buffer
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "web_fetch", `{"url":"http://203.0.113.9/x"}`)),
		fakemodel.Text("fetched"),
	))
	engine := mustEngine(t, policy.ModeEngagement,
		policy.WithScope(eng.Scope()), policy.WithROE(eng.ROE()), policy.WithClock(func() time.Time { return now }))
	loop := NewLoop(fake, mustRegistry(t, WebFetchTool(fetcher)), engine,
		audit.NewWriter(&auditBuf), testSystemPrompt, WithPrompter(prompter))

	if _, err := loop.Run(context.Background(), nil, "fetch it"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	seen := prompter.requests()
	if len(seen) != 1 || seen[0].Reason != policy.ReasonOutOfScope {
		t.Fatalf("permission prompts = %+v, want one out-of-scope prompt", seen)
	}
	if len(fetcher.urls) != 1 {
		t.Errorf("the allow-once prompt did not let the out-of-scope fetch run")
	}
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Verdict != audit.VerdictAllowOnce {
		t.Fatalf("audit records = %+v, want one allow-once", records)
	}
}

func TestLoopOutOfScopeDeniedDoesNotRun(t *testing.T) {
	now := loopClock(t, "2026-09-29T12:00:00Z")
	eng := engagementAt(t, scopeSource(true, true), now)
	fetcher := &recordingFetcher{}
	prompter := &scriptedPrompter{decide: func(PromptRequest) Decision { return DecisionDeny }}
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "web_fetch", `{"url":"http://203.0.113.9/x"}`)),
		fakemodel.Text("could not"),
	))
	engine := mustEngine(t, policy.ModeEngagement,
		policy.WithScope(eng.Scope()), policy.WithROE(eng.ROE()), policy.WithClock(func() time.Time { return now }))
	loop := NewLoop(fake, mustRegistry(t, WebFetchTool(fetcher)), engine,
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt, WithPrompter(prompter))

	if _, err := loop.Run(context.Background(), nil, "fetch it"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(fetcher.urls) != 0 {
		t.Errorf("a denied out-of-scope fetch still ran: %v", fetcher.urls)
	}
}

func TestLoopROEHardDeniesAreUnpromptable(t *testing.T) {
	now := loopClock(t, "2026-09-29T12:00:00Z")
	eng := engagementAt(t, scopeSource(false, true), now)

	tests := []struct {
		name string
		tool Tool
	}{
		{
			name: "exploit_allowed false hard-denies exploit-class tooling",
			tool: Tool{
				Name: "exploit_payload", Description: "exploit", Parameters: []byte(anySchema),
				ExploitClass: true,
				Handler:      func(context.Context, map[string]any) (string, error) { return "detonated", nil },
			},
		},
		{
			name: "destructive_forbidden true hard-denies destructive calls",
			tool: Tool{
				Name: "detonate_sample", Description: "destructive", Parameters: []byte(anySchema),
				Destructive: true,
				Handler:     func(context.Context, map[string]any) (string, error) { return "detonated", nil },
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ran int32
			tool := tt.tool
			inner := tool.Handler
			tool.Handler = func(ctx context.Context, args map[string]any) (string, error) {
				atomic.AddInt32(&ran, 1)
				return inner(ctx, args)
			}
			prompter := &scriptedPrompter{}
			var auditBuf bytes.Buffer
			fake := fakemodel.New(fakemodel.WithTurns(
				fakemodel.ToolCalls(fakemodel.Call("call-1", tool.Name, `{}`)),
				fakemodel.Text("done"),
			))
			engine := mustEngine(t, policy.ModeEngagement,
				policy.WithScope(eng.Scope()), policy.WithROE(eng.ROE()), policy.WithClock(func() time.Time { return now }))
			loop := NewLoop(fake, mustRegistry(t, tool), engine,
				audit.NewWriter(&auditBuf), testSystemPrompt, WithPrompter(prompter))

			if _, err := loop.Run(context.Background(), nil, "go"); err != nil {
				t.Fatalf("Run() = %v", err)
			}
			if atomic.LoadInt32(&ran) != 0 {
				t.Error("a hard-denied call executed")
			}
			if got := len(prompter.requests()); got != 0 {
				t.Errorf("permission prompts = %d, want 0 (ROE violations are never promptable)", got)
			}
			records := auditRecords(t, &auditBuf)
			if len(records) != 1 || records[0].Verdict != audit.VerdictHardDeny || records[0].Reason != string(policy.ReasonROE) {
				t.Fatalf("audit records = %+v, want one hard-deny/roe", records)
			}
		})
	}
}

func TestLoopTimeWindowHardDeny(t *testing.T) {
	withWindow := `apiVersion: styx.engagement/v1
name: windowed
targets:
  - 192.0.2.44
roe:
  exploit_allowed: true
  destructive_forbidden: true
  time_window:
    start: "08:00"
    end: "18:00"
    tz: America/New_York
`
	eng := engagementAt(t, withWindow, loopClock(t, "2026-09-30T12:00:00Z"))

	// 23:00 in New York is outside the 08:00–18:00 window; the in-scope fetch
	// must be hard-denied regardless of scope.
	outside := loopClock(t, "2026-09-29T23:00:00-04:00")
	fetcher := &recordingFetcher{body: "body"}
	var auditBuf bytes.Buffer
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "web_fetch", `{"url":"http://192.0.2.44/status"}`)),
		fakemodel.Text("done"),
	))
	engine := mustEngine(t, policy.ModeEngagement,
		policy.WithScope(eng.Scope()), policy.WithROE(eng.ROE()), policy.WithClock(func() time.Time { return outside }))
	loop := NewLoop(fake, mustRegistry(t, WebFetchTool(fetcher)), engine,
		audit.NewWriter(&auditBuf), testSystemPrompt)

	if _, err := loop.Run(context.Background(), nil, "fetch it"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(fetcher.urls) != 0 {
		t.Errorf("an out-of-window fetch ran: %v", fetcher.urls)
	}
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Verdict != audit.VerdictHardDeny || records[0].Reason != string(policy.ReasonROE) {
		t.Fatalf("audit records = %+v, want one hard-deny/roe", records)
	}
}

func TestLoopSSHLogsInScopeAutoAllows(t *testing.T) {
	now := loopClock(t, "2026-09-29T12:00:00Z")
	eng := engagementAt(t, scopeSource(true, true), now)
	fetcher := &recordingLogFetcher{out: "Sep 29 host sshd[1]: accepted\n"}
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "ssh_logs", `{"target":"192.0.2.44","command":"grep sshd /var/log/auth.log"}`)),
		fakemodel.Text("reviewed"),
	))
	engine := mustEngine(t, policy.ModeEngagement,
		policy.WithScope(eng.Scope()), policy.WithROE(eng.ROE()), policy.WithClock(func() time.Time { return now }))
	loop := NewLoop(fake, mustRegistry(t, SSHLogsTool(fetcher)), engine,
		audit.NewWriter(&bytes.Buffer{}), testSystemPrompt)

	if _, err := loop.Run(context.Background(), nil, "read auth log"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if fetcher.target != "192.0.2.44" || len(fetcher.command) == 0 {
		t.Errorf("ssh_logs did not reach the transport: %q %v", fetcher.target, fetcher.command)
	}
}
