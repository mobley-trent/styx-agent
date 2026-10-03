package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestMCPToolIsLenientAndCarriesSchema(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}`)
	var got map[string]any
	tool := MCPTool(MCPToolSource{
		Name:        "mcp__nmap__scan",
		Description: "scan",
		Parameters:  schema,
		Call: func(_ context.Context, args map[string]any) (string, error) {
			got = args
			return "scanned 10.0.0.5", nil
		},
	})

	if tool.Name != "mcp__nmap__scan" {
		t.Fatalf("tool name = %q", tool.Name)
	}
	// The harness validates MCP arguments itself, so the provider must not
	// schema-enforce a third-party server's schema (§5.5).
	if !tool.Lenient {
		t.Error("an MCP tool must be lenient; the harness validates its arguments")
	}
	desc := tool.Descriptor()
	if desc.Strict {
		t.Error("an MCP tool descriptor must not be strict")
	}
	if string(desc.Parameters) != string(schema) {
		t.Errorf("descriptor schema = %s, want the server's schema verbatim", desc.Parameters)
	}

	out, err := tool.Handler(context.Background(), map[string]any{"target": "10.0.0.5"})
	if err != nil {
		t.Fatalf("Handler() = %v, want nil", err)
	}
	if out != "scanned 10.0.0.5" {
		t.Errorf("Handler() = %q, want the server's result", out)
	}
	if got["target"] != "10.0.0.5" {
		t.Errorf("call args = %v, want the validated arguments", got)
	}
}

func TestMCPToolFailureIsAnError(t *testing.T) {
	tool := MCPTool(MCPToolSource{
		Name: "mcp__nmap__scan",
		Call: func(context.Context, map[string]any) (string, error) {
			return "", errors.New("the server crashed")
		},
	})
	_, err := tool.Handler(context.Background(), nil)
	if err == nil {
		t.Fatal("Handler() = nil error, want the server failure surfaced")
	}
	if !strings.Contains(err.Error(), "the server crashed") {
		t.Errorf("error = %q, want the server's failure preserved", err)
	}
}

func TestMCPToolWithoutCall(t *testing.T) {
	tool := MCPTool(MCPToolSource{Name: "mcp__x__y"})
	if _, err := tool.Handler(context.Background(), nil); err == nil {
		t.Fatal("Handler(no call) = nil error, want an error")
	}
}

func TestMCPToolDefaultSchema(t *testing.T) {
	tool := MCPTool(MCPToolSource{Name: "mcp__x__y", Call: func(context.Context, map[string]any) (string, error) {
		return "ok", nil
	}})
	var schema map[string]any
	if err := json.Unmarshal(tool.Parameters, &schema); err != nil {
		t.Fatalf("default schema is not valid JSON: %v", err)
	}
	if schema["type"] != "object" {
		t.Errorf("default schema type = %v, want object", schema["type"])
	}
}

func TestBuiltinToolsStayStrict(t *testing.T) {
	dir := t.TempDir()
	tool := ReadFileTool(dir)
	if tool.Lenient {
		t.Error("a built-in tool must not be lenient")
	}
	if !tool.Descriptor().Strict {
		t.Error("a built-in tool descriptor must be strict")
	}
}
