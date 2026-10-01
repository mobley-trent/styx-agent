package stubserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// TranscriptVersion is the only transcript schema version this build accepts.
// Transcript fixtures are versioned so replay stays compatible-by-contract
// (docs/spec.md §11.3).
const TranscriptVersion = "styx.transcript/v1"

// ErrTranscript is the sentinel wrapped by every transcript load failure.
var ErrTranscript = errors.New("stubserver: invalid transcript")

// Transcript is a scrubbed, versioned recording of a session, served through
// the stub server as its replay mode (§11.2, §11.3). It is data only.
type Transcript struct {
	Version string           `json:"version"`
	Model   string           `json:"model"`
	Turns   []TranscriptTurn `json:"turns"`
}

// TranscriptTurn is one recorded exchange: the request that was made and the
// response the model gave.
type TranscriptTurn struct {
	Request  TranscriptRequest  `json:"request"`
	Response TranscriptResponse `json:"response"`
}

// TranscriptRequest is the recorded request (advisory; replay serves turns in
// order rather than matching on the request).
type TranscriptRequest struct {
	Messages []Message        `json:"messages"`
	Tools    []TranscriptTool `json:"tools,omitempty"`
}

// TranscriptTool is a recorded tool descriptor.
type TranscriptTool struct {
	Name        string `json:"name"`
	Strict      bool   `json:"strict,omitempty"`
	Description string `json:"description,omitempty"`
}

// TranscriptResponse is the recorded model response, mapped onto a scripted
// Turn when replayed.
type TranscriptResponse struct {
	Reasoning []string           `json:"reasoning,omitempty"`
	Text      []string           `json:"text,omitempty"`
	ToolCalls []ScriptedToolCall `json:"tool_calls,omitempty"`
	Usage     *Usage             `json:"usage,omitempty"`
}

// LoadTranscript parses and validates a transcript fixture. Unknown versions
// are refused rather than interpreted on a best-effort basis.
func LoadTranscript(data []byte) (*Transcript, error) {
	var t Transcript
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTranscript, err)
	}
	if t.Version != TranscriptVersion {
		return nil, fmt.Errorf("%w: version %q: want %q", ErrTranscript, t.Version, TranscriptVersion)
	}
	if len(t.Turns) == 0 {
		return nil, fmt.Errorf("%w: no turns", ErrTranscript)
	}
	return &t, nil
}

// Script maps the transcript's recorded responses onto scripted turns.
func (t *Transcript) Script() []Turn {
	turns := make([]Turn, 0, len(t.Turns))
	for _, tt := range t.Turns {
		turns = append(turns, Turn{
			Reasoning: tt.Response.Reasoning,
			Text:      tt.Response.Text,
			ToolCalls: tt.Response.ToolCalls,
			Usage:     tt.Response.Usage,
		})
	}
	return turns
}

// Replay builds a stub server that serves a recorded transcript instead of a
// live model — replay is a stub mode, not a third mechanism (§11.2). The
// transcript's model is advertised by GET /models so client startup validation
// passes.
func Replay(t *Transcript, opts ...Option) *Server {
	base := []Option{
		WithScript(t.Script()...),
		WithRepeatLast(false),
	}
	if t.Model != "" {
		base = append(base, WithModels(t.Model))
	}
	return New(append(base, opts...)...)
}

// ReplayFile loads a transcript fixture from disk and serves it.
func ReplayFile(path string, opts ...Option) (*Server, error) {
	//nolint:gosec // the fixture path is test-controlled by design.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t, err := LoadTranscript(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return Replay(t, opts...), nil
}
