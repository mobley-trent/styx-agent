package repair

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

func readFileTool() model.Tool {
	return model.Tool{
		Name:   "read_file",
		Strict: true,
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"path":  {"type": "string"},
				"limit": {"type": "integer"}
			},
			"required": ["path"],
			"additionalProperties": false
		}`),
	}
}

func bashTool() model.Tool {
	return model.Tool{
		Name: "bash",
		Parameters: json.RawMessage(`{
			"type": "object",
			"properties": {
				"command": {"type": "string"},
				"env":     {"type": "array", "items": {"type": "string"}},
				"mode":    {"enum": ["fast", "safe"]}
			},
			"required": ["command"]
		}`),
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		call      model.ToolCall
		wantPaths []string // problem paths, empty means valid
		wantMsg   string
	}{
		{
			name: "valid",
			call: model.ToolCall{Name: "read_file", Arguments: `{"path":"README.md","limit":10}`},
		},
		{
			name: "empty arguments is the empty object",
			call: model.ToolCall{Name: "bash", Arguments: ""},
			// bash requires command, so this is invalid; see the dedicated
			// case below. Empty is still decoded, not treated as malformed.
			wantPaths: []string{"/command"},
			wantMsg:   "required property is missing",
		},
		{
			name:      "missing required",
			call:      model.ToolCall{Name: "read_file", Arguments: `{}`},
			wantPaths: []string{"/path"},
			wantMsg:   "required",
		},
		{
			name:      "wrong type",
			call:      model.ToolCall{Name: "read_file", Arguments: `{"path":1}`},
			wantPaths: []string{"/path"},
			wantMsg:   "expected string, got number",
		},
		{
			name:      "unexpected property",
			call:      model.ToolCall{Name: "read_file", Arguments: `{"path":"x","zzz":1}`},
			wantPaths: []string{"/zzz"},
			wantMsg:   "unexpected property",
		},
		{
			name:      "not an integer",
			call:      model.ToolCall{Name: "read_file", Arguments: `{"path":"x","limit":1.5}`},
			wantPaths: []string{"/limit"},
			wantMsg:   "expected integer",
		},
		{
			name:    "malformed JSON",
			call:    model.ToolCall{Name: "read_file", Arguments: `{"path":`},
			wantMsg: "not valid JSON",
		},
		{
			name:    "more than one JSON value",
			call:    model.ToolCall{Name: "read_file", Arguments: `{"path":"x"}{"path":"y"}`},
			wantMsg: "more than one JSON value",
		},
		{
			name:      "array item wrong type",
			call:      model.ToolCall{Name: "bash", Arguments: `{"command":"ls","env":["A",2]}`},
			wantPaths: []string{"/env/1"},
			wantMsg:   "expected string",
		},
		{
			name:      "enum violation",
			call:      model.ToolCall{Name: "bash", Arguments: `{"command":"ls","mode":"turbo"}`},
			wantPaths: []string{"/mode"},
			wantMsg:   "not one of the allowed values",
		},
		{
			name:    "unknown tool",
			call:    model.ToolCall{Name: "bogus", Arguments: `{}`},
			wantMsg: "unknown tool",
		},
	}

	v := NewValidator([]model.Tool{readFileTool(), bashTool()})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.call)
			if len(tt.wantPaths) == 0 && tt.wantMsg == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want feedback")
			}
			var fb *Feedback
			if !errors.As(err, &fb) {
				t.Fatalf("Validate() error = %T, want *Feedback", err)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantMsg)
			}
			var gotPaths []string
			for _, p := range fb.Problems {
				gotPaths = append(gotPaths, p.Path)
			}
			if len(tt.wantPaths) > 0 && strings.Join(gotPaths, ",") != strings.Join(tt.wantPaths, ",") {
				t.Errorf("problem paths = %v, want %v", gotPaths, tt.wantPaths)
			}
			// The feedback must name the tool and echo the raw arguments so
			// the model can repair what it actually emitted.
			if !strings.Contains(err.Error(), tt.call.Name) {
				t.Errorf("error = %q, want it to name tool %q", err, tt.call.Name)
			}
			if tt.call.Arguments != "" && !strings.Contains(err.Error(), tt.call.Arguments) {
				t.Errorf("error = %q, want it to echo the raw arguments", err)
			}
		})
	}
}

// TestValidateCollectsEveryProblem checks a call with several defects reports
// them all at once.
func TestValidateCollectsEveryProblem(t *testing.T) {
	v := NewValidator([]model.Tool{readFileTool()})
	err := v.Validate(model.ToolCall{Name: "read_file", Arguments: `{"limit":"soon","zzz":true}`})
	var fb *Feedback
	if !errors.As(err, &fb) {
		t.Fatalf("Validate() error = %v, want *Feedback", err)
	}
	if len(fb.Problems) != 3 {
		t.Fatalf("problems = %d, want 3 (missing path, bad limit, unexpected zzz)", len(fb.Problems))
	}
}

// TestValidatorFailsClosedOnBadSchema pins that a tool whose declared schema
// cannot be parsed never validates — the harness cannot know what is legal.
func TestValidatorFailsClosedOnBadSchema(t *testing.T) {
	v := NewValidator([]model.Tool{{Name: "broken", Parameters: json.RawMessage(`{not json`)}})
	err := v.Validate(model.ToolCall{Name: "broken", Arguments: `{}`})
	if err == nil {
		t.Fatal("Validate() = nil, want fail-closed feedback")
	}
	if !strings.Contains(err.Error(), "cannot validate") {
		t.Errorf("error = %q, want a cannot-validate message", err)
	}
}

// TestRepairBudgetAborts is the repair acceptance: a malformed call consumes a
// structured repair, and once the budget is spent the turn aborts with a
// visible error rather than looping.
func TestRepairBudgetAborts(t *testing.T) {
	v := NewValidator([]model.Tool{readFileTool()})
	bad := model.ToolCall{Name: "read_file", Arguments: `{"path":`}

	// The narrow bound: one repair, then abort.
	r := NewRepairer(v, 1)
	err := r.Check(bad)
	var fb *Feedback
	if !errors.As(err, &fb) {
		t.Fatalf("first Check() = %v, want a structured repair", err)
	}
	if r.Used() != 1 || r.Remaining() != 0 {
		t.Errorf("after one repair: used=%d remaining=%d, want 1/0", r.Used(), r.Remaining())
	}
	err = r.Check(bad)
	if !errors.Is(err, ErrTurnAborted) {
		t.Fatalf("second Check() = %v, want ErrTurnAborted", err)
	}
}

// TestRepairBudgetIsPerTurn pins the spec's 2-repair bound and that a valid
// call needs no repair.
func TestRepairBudgetIsPerTurn(t *testing.T) {
	v := NewValidator([]model.Tool{readFileTool()})
	r := NewRepairer(v, 2)

	if err := r.Check(model.ToolCall{Name: "read_file", Arguments: `{"path":"ok"}`}); err != nil {
		t.Fatalf("valid Check() = %v, want nil", err)
	}
	for i := 0; i < 2; i++ {
		err := r.Check(model.ToolCall{Name: "read_file", Arguments: `{"path":`})
		var fb *Feedback
		if !errors.As(err, &fb) {
			t.Fatalf("repair %d = %v, want structured feedback", i+1, err)
		}
	}
	if !errors.Is(r.Check(model.ToolCall{Name: "read_file", Arguments: `{"path":`}), ErrTurnAborted) {
		t.Fatal("third invalid Check() = nil, want ErrTurnAborted after 2 repairs")
	}
}

// TestRepairFromFakeModelToolCall is the fault acceptance end to end: a
// malformed tool call emitted by the model yields one structured repair, and a
// second malformed call aborts the turn with a visible error.
func TestRepairFromFakeModelToolCall(t *testing.T) {
	f := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(model.ToolCall{ID: "c1", Name: "read_file", Arguments: `{"path":`}),
		fakemodel.ToolCalls(model.ToolCall{ID: "c2", Name: "read_file", Arguments: `{"limit":`}),
	))
	r := NewRepairer(NewValidator([]model.Tool{readFileTool()}), 1)

	first := modelToolCall(t, f)
	err := r.Check(first)
	var fb *Feedback
	if !errors.As(err, &fb) {
		t.Fatalf("first malformed call = %v, want one structured repair", err)
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("feedback = %q, want it to explain the JSON problem", err)
	}

	second := modelToolCall(t, f)
	if err := r.Check(second); !errors.Is(err, ErrTurnAborted) {
		t.Fatalf("second malformed call = %v, want ErrTurnAborted", err)
	}
}

// modelToolCall streams the fake model's next turn and returns its first tool
// call, failing if the turn carries none.
func modelToolCall(t *testing.T, f *fakemodel.Fake) model.ToolCall {
	t.Helper()
	ch, err := f.StreamTurn(context.Background(), model.ModelRequest{})
	if err != nil {
		t.Fatalf("StreamTurn() error = %v", err)
	}
	for ev := range ch {
		if ev.Kind == model.EventToolCall {
			return *ev.ToolCall
		}
	}
	t.Fatal("fake turn carried no tool call")
	return model.ToolCall{}
}
