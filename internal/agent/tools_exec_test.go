package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// fakeExecutor records exec calls and answers with a canned result.
type fakeExecutor struct {
	shells []string
	codes  []codeCall
	result string
	err    error
}

type codeCall struct{ lang, code string }

func (f *fakeExecutor) Shell(_ context.Context, command string) (string, error) {
	f.shells = append(f.shells, command)
	return f.result, f.err
}

func (f *fakeExecutor) Code(_ context.Context, lang, code string) (string, error) {
	f.codes = append(f.codes, codeCall{lang: lang, code: code})
	return f.result, f.err
}

func TestBashToolDispatchesToTheExecutor(t *testing.T) {
	exec := &fakeExecutor{result: "ok\n"}
	tool := BashTool(exec)

	got, err := tool.Handler(context.Background(), map[string]any{"command": "go test ./..."})
	if err != nil || got != "ok\n" {
		t.Fatalf("Bash handler = %q/%v, want the executor result", got, err)
	}
	if len(exec.shells) != 1 || exec.shells[0] != "go test ./..." {
		t.Errorf("executor shells = %v, want the command verbatim", exec.shells)
	}

	if _, err := tool.Handler(context.Background(), map[string]any{}); err == nil {
		t.Error("Bash handler with no command = nil error, want a validation error")
	}
}

func TestCodeExecToolDispatchesLangAndCode(t *testing.T) {
	exec := &fakeExecutor{result: "42"}
	tool := CodeExecTool(exec)

	got, err := tool.Handler(context.Background(), map[string]any{"lang": "python3", "code": "print(42)"})
	if err != nil || got != "42" {
		t.Fatalf("CodeExec handler = %q/%v, want the executor result", got, err)
	}
	if len(exec.codes) != 1 || exec.codes[0] != (codeCall{lang: "python3", code: "print(42)"}) {
		t.Errorf("executor codes = %+v, want lang/code passed through", exec.codes)
	}
}

func TestExecToolsRefuseWithoutAContainer(t *testing.T) {
	if _, err := BashTool(nil).Handler(context.Background(), map[string]any{"command": "ls"}); err == nil ||
		!strings.Contains(err.Error(), "container") {
		t.Errorf("Bash with no executor error = %v, want a container-unavailable refusal", err)
	}
	if _, err := CodeExecTool(nil).Handler(context.Background(), map[string]any{"lang": "python3", "code": "1"}); err == nil {
		t.Error("CodeExec with no executor = nil error, want a refusal")
	}
}

func TestExecToolErrorsPropagate(t *testing.T) {
	exec := &fakeExecutor{err: errors.New("daemon down")}
	if _, err := BashTool(exec).Handler(context.Background(), map[string]any{"command": "ls"}); err == nil {
		t.Error("Bash handler = nil error, want the executor error")
	}
}

func TestLoopStampsIsolationInAudit(t *testing.T) {
	dir := workspace(t, map[string]string{"main.go": "package main\n"})
	var auditBuf bytes.Buffer
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`)),
		fakemodel.Text("done"),
	))
	loop := NewLoop(fake, mustRegistry(t, ReadFileTool(dir)), mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		WithIsolationProvider(func() audit.Isolation { return audit.IsolationDegraded }))

	if _, err := loop.Run(context.Background(), nil, "read it"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	records := auditRecords(t, &auditBuf)
	if len(records) != 1 || records[0].Isolation != audit.IsolationDegraded {
		t.Fatalf("audit records = %+v, want the degraded isolation stamped", records)
	}
}
