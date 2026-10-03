package app

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mobley-trent/styx-agent/internal/mcpclient"
	"github.com/mobley-trent/styx-agent/internal/mcpclient/fakeserver"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// nmapSchema is the scan server's input schema: target required, strict.
var nmapSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"target": map[string]any{"type": "string"},
	},
	"required":             []any{"target"},
	"additionalProperties": false,
}

func TestMCPToolFollowsNormativeOrder(t *testing.T) {
	dir := t.TempDir()
	// The MCP family is pre-authorized for the session so the test asserts
	// the flow, not the prompt; the policy gate still resolves each call.
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"permissions:\n  rules:\n    - tool: mcp__*\n      action: allow\n"+
			"mcp:\n  servers:\n    - name: nmap\n      command: nmap-mcp\n")

	server := fakeserver.New("nmap")
	server.AddTool("scan", "Run an nmap scan against a target.", nmapSchema)
	server.SetHandler(func(_ context.Context, _ string, args map[string]any) (string, error) {
		return "nmap: " + args["target"].(string) + " is up", nil
	})

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("m1", "mcp__nmap__scan", `{"target":"10.0.0.5"}`)),
		fakemodel.Text("the target is up"),
	))

	opts := buildOptions(t, dir, fake)
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// The MCP tool is an ordinary registry member.
	if _, ok := h.Tools.Lookup("mcp__nmap__scan"); !ok {
		t.Fatal("the session registry has no mcp__nmap__scan tool")
	}

	if err := h.Submit(context.Background(), "scan 10.0.0.5"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}

	// The tool result is the server's rendered output.
	var result string
	for _, m := range h.Messages() {
		if m.Role == model.RoleTool && m.ToolCallID == "m1" {
			result = m.Content
		}
	}
	if result != "nmap: 10.0.0.5 is up" {
		t.Errorf("tool result = %q, want the MCP server's output", result)
	}

	// Normative order: the call was validated, decided, and audited before
	// dispatch. The audit trail records it with the policy verdict.
	events, err := h.sessions.Replay(dir, h.SessionID())
	if err != nil {
		t.Fatalf("Replay() = %v", err)
	}
	var called bool
	for _, ev := range events {
		if ev.Kind == sessions.KindToolCall && ev.Tool == "mcp__nmap__scan" {
			called = true
			if ev.Verdict == "" {
				t.Error("the tool_call event carries no verdict")
			}
		}
	}
	if !called {
		t.Error("the MCP tool call was not persisted as a tool_call event")
	}

	// The lifecycle is persisted too: connecting then ready.
	var ready bool
	for _, ev := range events {
		if ev.Kind == sessions.KindMCP && ev.Server == "nmap" && ev.Status == string(mcpclient.StatusReady) {
			ready = true
		}
	}
	if !ready {
		t.Error("no ready MCP lifecycle event was persisted")
	}
}

func TestMCPMalformedArgumentsAreRepairedNotPassedThrough(t *testing.T) {
	dir := t.TempDir()
	// No permission rule: the engine prompts, and the deny-by-default
	// prompter refuses, so nothing reaches the server even if validation
	// passed. The assertion below is that validation catches it first.
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: nmap\n      command: nmap-mcp\n")

	server := fakeserver.New("nmap")
	server.AddTool("scan", "Run an nmap scan against a target.", nmapSchema)
	var sawCall bool
	server.SetHandler(func(_ context.Context, _ string, _ map[string]any) (string, error) {
		sawCall = true
		return "should not run", nil
	})

	// The model emits a call missing the required "target" property.
	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("m1", "mcp__nmap__scan", `{"scan_type":"syn"}`)),
		fakemodel.Text("I need the target"),
	))

	opts := buildOptions(t, dir, fake)
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if err := h.Submit(context.Background(), "scan it"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}

	if sawCall {
		t.Error("the malformed call reached the MCP server; the harness must validate first")
	}
	// The model received a structured repair, not a silent pass-through.
	var repaired bool
	for _, m := range h.Messages() {
		if m.Role == model.RoleTool && m.ToolCallID == "m1" && strings.Contains(m.Content, "target") {
			repaired = true
		}
	}
	if !repaired {
		t.Error("the model was not told its MCP arguments were invalid")
	}
}

func TestMCPToolFailureIsVisibleNotFatal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"permissions:\n  rules:\n    - tool: mcp__*\n      action: allow\n"+
			"mcp:\n  servers:\n    - name: nmap\n      command: nmap-mcp\n")

	server := fakeserver.New("nmap")
	server.AddTool("scan", "Run an nmap scan against a target.", nmapSchema)
	server.SetHandler(func(_ context.Context, _ string, _ map[string]any) (string, error) {
		return "", errors.New("the scan binary crashed")
	})

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("m1", "mcp__nmap__scan", `{"target":"10.0.0.5"}`)),
		fakemodel.Text("the scan failed, I will try another approach"),
	))

	opts := buildOptions(t, dir, fake)
	opts.MCPConnector = server.Connector()

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// The loop does not crash: the failure is a tool result the model sees.
	if err := h.Submit(context.Background(), "scan 10.0.0.5"); err != nil {
		t.Fatalf("Submit() = %v, want the turn to complete with a tool-level failure", err)
	}
	var failure string
	for _, m := range h.Messages() {
		if m.Role == model.RoleTool && m.ToolCallID == "m1" {
			failure = m.Content
		}
	}
	if !strings.Contains(failure, "scan binary crashed") {
		t.Errorf("tool result = %q, want the server failure surfaced to the model", failure)
	}
}

func TestMCPLaunchFailureIsVisibleAndNonFatal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: ghidra\n      command: ghidra-mcp\n")

	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("no tools needed")))

	opts := buildOptions(t, dir, fake)
	opts.MCPConnector = fakeserver.FailingConnector(errors.New("executable not found"))

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v, want a non-fatal launch failure", err)
	}
	defer func() { _ = h.Close() }()

	if _, ok := h.Tools.Lookup("mcp__ghidra__anything"); ok {
		t.Error("a failed server contributed a tool")
	}

	// The failure is visible in the status the TUI renders.
	var status string
	for _, s := range h.MCPServers() {
		if s.Name == "ghidra" {
			status = string(s.Status)
		}
	}
	if status != string(mcpclient.StatusFailed) {
		t.Errorf("ghidra status = %q, want failed", status)
	}

	// And the session still works.
	if err := h.Submit(context.Background(), "hello"); err != nil {
		t.Fatalf("Submit() = %v, want the session to keep working", err)
	}
}

func TestMCPNotRelaunchedOnModeSwitch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: nmap\n      command: nmap-mcp\n")

	var mu sync.Mutex
	connects := 0
	server := fakeserver.New("nmap")
	server.AddTool("scan", "Run an nmap scan against a target.", nmapSchema)
	base := server.Connector()
	countingConnector := func(ctx context.Context, srv mcpclient.Server) (*mcp.ClientSession, error) {
		mu.Lock()
		connects++
		mu.Unlock()
		return base(ctx, srv)
	}

	fake := fakemodel.New()
	opts := buildOptions(t, dir, fake)
	opts.MCPConnector = countingConnector

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// A mode switch rebuilds the registry and loop; it must not relaunch the
	// MCP servers (their tools are re-gated per call by the new engine).
	if err := h.ActivateEngagement(context.Background(), engagementFixture); err != nil {
		t.Fatalf("ActivateEngagement() = %v", err)
	}
	if err := h.Deactivate(); err != nil {
		t.Fatalf("Deactivate() = %v", err)
	}

	mu.Lock()
	got := connects
	mu.Unlock()
	if got != 1 {
		t.Errorf("server connects = %d, want 1 (no relaunch on mode switch)", got)
	}

	// The tool is still registered after the switches.
	if _, ok := h.Tools.Lookup("mcp__nmap__scan"); !ok {
		t.Error("mcp__nmap__scan is missing after a mode switch")
	}
}

func TestMCPDisabledServerIsNotLaunched(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join(".styx", "config.yaml"),
		"mcp:\n  servers:\n    - name: nmap\n      command: nmap-mcp\n      disabled: true\n")

	fake := fakemodel.New()
	opts := buildOptions(t, dir, fake)

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if len(h.MCPServers()) != 0 {
		t.Errorf("MCPServers() = %+v, want none for a disabled server", h.MCPServers())
	}
}
