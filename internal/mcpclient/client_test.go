package mcpclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/mcpclient"
	"github.com/mobley-trent/styx-agent/internal/mcpclient/fakeserver"
)

// nmapSchema is a representative tool schema, the shape a scan server
// advertises.
var nmapSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"target":    map[string]any{"type": "string"},
		"scan_type": map[string]any{"type": "string"},
	},
	"required":             []any{"target"},
	"additionalProperties": false,
}

// scanServer is a scripted MCP server with a working scan tool, a version
// tool, and a tool that fails server-side.
func scanServer() *fakeserver.Server {
	f := fakeserver.New("nmap")
	f.AddTool("scan", "Run an nmap scan against a target.", nmapSchema)
	f.AddTool("version", "Report the nmap version.", map[string]any{"type": "object", "properties": map[string]any{}})
	f.AddTool("boom", "A tool that fails server-side.", map[string]any{"type": "object", "properties": map[string]any{}})
	f.SetHandler(func(_ context.Context, tool string, args map[string]any) (string, error) {
		switch tool {
		case "scan":
			return "scan of " + args["target"].(string) + " complete", nil
		case "version":
			return "nmap 7.95", nil
		case "boom":
			return "", errors.New("server-side failure")
		}
		return "", errors.New("unknown tool")
	})
	return f
}

func TestManagerDiscoversTools(t *testing.T) {
	f := scanServer()
	var events []mcpclient.Event
	m := mcpclient.New(mcpclient.WithConnector(f.Connector()), mcpclient.WithEmitter(func(ev mcpclient.Event) {
		events = append(events, ev)
	}))

	m.Start(context.Background(), []mcpclient.Server{{Name: "nmap", Command: "nmap-mcp"}})

	tools := m.Tools()
	if len(tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(tools))
	}
	// mcpclient.Tools are exposed under the mcp__<server>__<tool> namespace.
	var names []string
	for _, tool := range tools {
		names = append(names, tool.Namespaced())
	}
	want := "[mcp__nmap__boom mcp__nmap__scan mcp__nmap__version]"
	if got := "[" + strings.Join(names, " ") + "]"; got != want {
		t.Errorf("namespaced tools = %v, want %s", names, want)
	}

	// The schema is carried verbatim for the repair layer to validate against.
	var scan mcpclient.Tool
	for _, tool := range tools {
		if tool.Name == "scan" {
			scan = tool
		}
	}
	var schema map[string]any
	if err := json.Unmarshal(scan.Schema, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema["type"] != "object" {
		t.Errorf("schema type = %v, want object", schema["type"])
	}

	// The lifecycle is reported: connecting, then ready with a tool count.
	if len(events) < 2 || events[0].Status != mcpclient.StatusConnecting {
		t.Fatalf("events = %+v, want a connecting transition first", events)
	}
	last := events[len(events)-1]
	if last.Status != mcpclient.StatusReady || last.Tools != 3 {
		t.Errorf("last event = %+v, want ready with 3 tools", last)
	}
}

func TestManagerCallRoundTrip(t *testing.T) {
	m := mcpclient.New(mcpclient.WithConnector(scanServer().Connector()))
	m.Start(context.Background(), []mcpclient.Server{{Name: "nmap", Command: "nmap-mcp"}})

	got, err := m.Call(context.Background(), "nmap", "scan", map[string]any{"target": "10.0.0.5"})
	if err != nil {
		t.Fatalf("Call() = %v, want nil", err)
	}
	if got != "scan of 10.0.0.5 complete" {
		t.Errorf("Call() = %q, want the server's result", got)
	}
}

func TestManagerCallServerSideErrorIsToolError(t *testing.T) {
	m := mcpclient.New(mcpclient.WithConnector(scanServer().Connector()))
	m.Start(context.Background(), []mcpclient.Server{{Name: "nmap", Command: "nmap-mcp"}})

	if _, err := m.Call(context.Background(), "nmap", "boom", nil); err == nil {
		t.Fatal("Call(boom) = nil error, want a tool-level error")
	}
}

func TestManagerLaunchFailureIsVisibleNotFatal(t *testing.T) {
	var events []mcpclient.Event
	m := mcpclient.New(
		mcpclient.WithConnector(fakeserver.FailingConnector(errors.New("executable not found"))),
		mcpclient.WithEmitter(func(ev mcpclient.Event) { events = append(events, ev) }),
	)

	// Start returns: a dead server never aborts the session.
	m.Start(context.Background(), []mcpclient.Server{{Name: "ghidra", Command: "missing"}})

	if len(m.Tools()) != 0 {
		t.Errorf("tools = %d, want none from a failed server", len(m.Tools()))
	}
	statuses := m.Statuses()
	if len(statuses) != 1 || statuses[0].Status != mcpclient.StatusFailed {
		t.Fatalf("statuses = %+v, want one failed server", statuses)
	}
	if !strings.Contains(statuses[0].Detail, "executable not found") {
		t.Errorf("detail = %q, want the launch failure", statuses[0].Detail)
	}
	var failed bool
	for _, ev := range events {
		if ev.Status == mcpclient.StatusFailed {
			failed = true
		}
	}
	if !failed {
		t.Error("no failed lifecycle event was emitted")
	}
}

func TestManagerCallUnconnectedServerIsToolError(t *testing.T) {
	m := mcpclient.New()
	if _, err := m.Call(context.Background(), "nmap", "scan", nil); err == nil {
		t.Fatal("Call(unconnected) = nil error, want a tool-level error")
	}
}

func TestManagerCloseIsClean(t *testing.T) {
	var events []mcpclient.Event
	var mu sync.Mutex
	m := mcpclient.New(
		mcpclient.WithConnector(scanServer().Connector()),
		mcpclient.WithEmitter(func(ev mcpclient.Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}),
	)
	m.Start(context.Background(), []mcpclient.Server{{Name: "nmap", Command: "nmap-mcp"}})

	if err := m.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	// A clean close is not a disconnect failure.
	mu.Lock()
	defer mu.Unlock()
	for _, ev := range events {
		if ev.Status == mcpclient.StatusFailed {
			t.Errorf("close emitted a failure event: %+v", ev)
		}
	}
}

func TestManagerReportsDisconnect(t *testing.T) {
	f := scanServer()
	var events []mcpclient.Event
	var mu sync.Mutex
	m := mcpclient.New(
		mcpclient.WithConnector(f.Connector()),
		mcpclient.WithEmitter(func(ev mcpclient.Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}),
	)
	m.Start(context.Background(), []mcpclient.Server{{Name: "nmap", Command: "nmap-mcp"}})

	// The server crashes mid-session.
	f.Disconnect()

	// The watcher reports the disconnect as a lifecycle event (async, so poll).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		failed := false
		for _, ev := range events {
			if ev.Status == mcpclient.StatusFailed {
				failed = true
			}
		}
		mu.Unlock()
		if failed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The disconnect is visible, not a crash: a call now returns a tool-level
	// error the model sees.
	if _, err := m.Call(context.Background(), "nmap", "scan", map[string]any{"target": "10.0.0.5"}); err == nil {
		t.Error("Call(after disconnect) = nil error, want a tool-level error")
	}
}

func TestManagerStartIsIdempotent(t *testing.T) {
	m := mcpclient.New(mcpclient.WithConnector(scanServer().Connector()))
	servers := []mcpclient.Server{{Name: "nmap", Command: "nmap-mcp"}}
	m.Start(context.Background(), servers)
	m.Start(context.Background(), servers)
	if got := len(m.Tools()); got != 3 {
		t.Errorf("tools after two Starts = %d, want 3 (no duplicates)", got)
	}
}

func TestNamespacedNameRoundTrip(t *testing.T) {
	name := mcpclient.NamespacedName("nmap", "scan")
	if name != "mcp__nmap__scan" {
		t.Fatalf("mcpclient.NamespacedName() = %q", name)
	}
	server, tool, ok := mcpclient.SplitName(name)
	if !ok || server != "nmap" || tool != "scan" {
		t.Errorf("mcpclient.SplitName(%q) = %q/%q/%v", name, server, tool, ok)
	}
	if _, _, ok := mcpclient.SplitName("read_file"); ok {
		t.Error("mcpclient.SplitName(read_file) reported an MCP tool")
	}
	if _, _, ok := mcpclient.SplitName("mcp__onlyserver"); ok {
		t.Error("mcpclient.SplitName(mcp__onlyserver) reported a valid MCP tool")
	}
}
