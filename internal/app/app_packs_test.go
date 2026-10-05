package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/mcpclient/fakeserver"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// recordingExecutor is a session executor that records the calls that reach it,
// so a test can prove a denied call never executed.
type recordingExecutor struct {
	shells []string
	codes  []string
}

func (r *recordingExecutor) Shell(_ context.Context, command string) (string, error) {
	r.shells = append(r.shells, command)
	return "ran", nil
}

func (r *recordingExecutor) Code(_ context.Context, _ string, code string) (string, error) {
	r.codes = append(r.codes, code)
	return "ran", nil
}

func TestPackInjectionFromEngagement(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), func() Options {
		o := buildOptions(t, dir, fakemodel.New())
		o.Engagement = engagementFixture
		return o
	}())
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if !strings.Contains(h.Prompt, "# Red team workflow (four phases)") {
		t.Error("engagement build did not inject the red team full workflow")
	}
	if strings.Contains(h.Prompt, "# Red team (guidance)") {
		t.Error("engagement build kept the red team compact section")
	}
	if got := h.Status(false).Packs; got != "coding+red-team" {
		t.Errorf("status packs = %q, want coding+red-team", got)
	}

	out, err := h.command("pack", "")
	if err != nil {
		t.Fatalf("/pack = %v", err)
	}
	for _, want := range []string{"red-team", "full", "engagement active"} {
		if !strings.Contains(out, want) {
			t.Errorf("/pack output = %q, want %q", out, want)
		}
	}
}

func TestPackInjectionFromREMCP(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: ghidra\n      command: ghidra-mcp\n")

	server := fakeserver.New("ghidra")
	server.AddTool("decompile", "Decompile a function.", nmapSchema)

	opts := buildOptions(t, dir, fakemodel.New())
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if !strings.Contains(h.Prompt, "# Reverse engineering & malware workflow") {
		t.Error("RE MCP build did not inject the RE full workflow")
	}
	if got := h.Status(false).Packs; got != "coding+re" {
		t.Errorf("status packs = %q, want coding+re", got)
	}
	// The RE pack's allowlist delta rides the detected domain: the harness's
	// arbitrary execution surface is destructive-tagged end to end.
	tool, ok := h.Tools.Lookup("code_exec")
	if !ok {
		t.Fatal("code_exec is not registered")
	}
	if !tool.Destructive {
		t.Error("code_exec is not destructive-tagged with the RE pack active")
	}
}

func TestPackInjectionFromLogArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "auth.log", "failed login for root\n")

	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if !strings.Contains(h.Prompt, "# Blue team workflow (log triage & incident response)") {
		t.Error("log artifact build did not inject the blue team full workflow")
	}
	if got := h.Status(false).Packs; got != "coding+blue-team" {
		t.Errorf("status packs = %q, want coding+blue-team", got)
	}
	// A code file must not activate the domain.
	plain := t.TempDir()
	writeFile(t, plain, "main.go", "package main\n")
	h2, err := Build(context.Background(), buildOptions(t, plain, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h2.Close() }()
	if strings.Contains(h2.Prompt, "# Blue team workflow") {
		t.Error("a plain source tree activated the blue team pack")
	}
}

func TestPromptPrefixIsFixedForTheSession(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "auth.log", "x\n")
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("ok")))
	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	before := h.Prompt
	if err := h.Submit(context.Background(), "triage this"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if h.Prompt != before {
		t.Error("the system prompt changed mid-session; the byte-stable prefix was swapped")
	}
}

// permissiveEngagement allows exploitation and does not forbid destructive
// calls, so the destructive-tag behavior (never auto-allow) is observable.
const permissiveEngagement = `apiVersion: styx.engagement/v1
name: pack-permissive
operator: eddy
targets:
  - 10.0.0.0/24
roe:
  exploit_allowed: true
  destructive_forbidden: false
`

// TestRedTeamExploitToolHardDenied proves the red team pack's exploit-class
// delta reaches the policy layer: with exploit_allowed false, an in-scope
// exploit tool is hard-denied, never auto-allowed, and never dispatched.
func TestRedTeamExploitToolHardDenied(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: sqlmap\n      command: sqlmap-mcp\n")
	engPath := writeFile(t, dir, "engagement.yaml", mcpEngagement)

	server := fakeserver.New("sqlmap")
	server.AddTool("run", "Exploit an injection.", nmapSchema)
	var dispatched bool
	server.SetHandler(func(_ context.Context, _ string, _ map[string]any) (string, error) {
		dispatched = true
		return "pwned", nil
	})

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "mcp__sqlmap__run", `{"target":"10.0.0.5"}`)),
		fakemodel.Text("the engagement does not permit exploitation"),
	))

	opts := buildOptions(t, dir, fake)
	opts.Engagement = engPath
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if err := h.Submit(context.Background(), "exploit it"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if dispatched {
		t.Error("an exploit-class call reached the server despite exploit_allowed false")
	}

	var sawROE bool
	for _, rec := range readAuditRecords(t, dir) {
		if rec.Tool == "mcp__sqlmap__run" {
			if rec.Verdict != audit.VerdictHardDeny || rec.Reason != string(policy.ReasonROE) {
				t.Errorf("audit verdict = %q/%s, want hard-deny/roe", rec.Verdict, rec.Reason)
			}
			sawROE = true
		}
	}
	if !sawROE {
		t.Error("no audit record for the exploit-class call")
	}
}

// TestREDetonationDestructiveTagged proves the destructive tag rides the RE
// pack from the registry into the audit: with destructive_forbidden true, the
// tagged exec call is hard-denied and never dispatched.
func TestREDetonationDestructiveTagged(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: ghidra\n      command: ghidra-mcp\n")
	engPath := writeFile(t, dir, "engagement.yaml", mcpEngagement)

	server := fakeserver.New("ghidra")
	server.AddTool("decompile", "Decompile a function.", nmapSchema)

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "code_exec", `{"lang":"python","code":"open('/tmp/sample','rb')"}`)),
		fakemodel.Text("the engagement forbids destructive calls"),
	))

	exec := &recordingExecutor{}
	opts := buildOptions(t, dir, fake)
	opts.Engagement = engPath
	opts.Executor = exec
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if err := h.Submit(context.Background(), "detonate the sample"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if len(exec.codes) != 0 {
		t.Errorf("destructive exec reached the executor: %v", exec.codes)
	}

	var sawROE bool
	for _, rec := range readAuditRecords(t, dir) {
		if rec.Tool == "code_exec" {
			if rec.Verdict != audit.VerdictHardDeny || rec.Reason != string(policy.ReasonROE) {
				t.Errorf("audit verdict = %q/%s, want hard-deny/roe", rec.Verdict, rec.Reason)
			}
			sawROE = true
		}
	}
	if !sawROE {
		t.Error("no audit record for the destructive exec call")
	}
}

// TestREDetonationNeverAutoAllows proves the other half of §8.3: when the
// engagement does not forbid destructive calls, an in-scope destructive call is
// still prompted, never auto-allowed by the scope match.
func TestREDetonationNeverAutoAllows(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: ghidra\n      command: ghidra-mcp\n")
	engPath := writeFile(t, dir, "engagement.yaml", permissiveEngagement)

	server := fakeserver.New("ghidra")
	server.AddTool("detonate", "Run a sample.", nmapSchema)
	var dispatched bool
	server.SetHandler(func(_ context.Context, _ string, _ map[string]any) (string, error) {
		dispatched = true
		return "ran the sample", nil
	})

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "mcp__ghidra__detonate", `{"target":"10.0.0.5"}`)),
		fakemodel.Text("I need explicit authorization to detonate"),
	))

	opts := buildOptions(t, dir, fake)
	opts.Engagement = engPath
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// The registry carries the tag.
	tool, ok := h.Tools.Lookup("mcp__ghidra__detonate")
	if !ok {
		t.Fatal("the detonation tool is not registered")
	}
	if !tool.Destructive {
		t.Fatal("the detonation tool is not destructive-tagged")
	}

	// The deny-by-default prompter stands in for "no operator pre-authorized
	// it": the in-scope call is prompted (and denied), not auto-allowed.
	if err := h.Submit(context.Background(), "detonate it"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if dispatched {
		t.Error("a destructive in-scope call was auto-allowed and dispatched")
	}
	var sawDestructive bool
	for _, rec := range readAuditRecords(t, dir) {
		if rec.Tool == "mcp__ghidra__detonate" {
			if rec.Reason != string(policy.ReasonDestructive) {
				t.Errorf("audit reason = %q, want %q", rec.Reason, policy.ReasonDestructive)
			}
			sawDestructive = true
		}
	}
	if !sawDestructive {
		t.Error("no audit record for the in-scope destructive call")
	}
}
