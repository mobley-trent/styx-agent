package agent

import (
	"context"
	"reflect"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

func addrs(targets []policy.Target) []string {
	if len(targets) == 0 {
		return nil
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Addr)
	}
	return out
}

func TestMCPScopeTargetsExtraction(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
		want []string
	}{
		{
			name: "target key contributes its value",
			args: map[string]any{"target": "10.0.2.15"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "host key",
			args: map[string]any{"host": "app.acme.example"},
			want: []string{"app.acme.example"},
		},
		{
			name: "camelCase hostname key",
			args: map[string]any{"targetHost": "10.0.2.15"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "snake_case ip key",
			args: map[string]any{"ip_address": "10.0.2.15"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "URL key reduces to host",
			args: map[string]any{"url": "https://app.acme.example/scan?x=1"},
			want: []string{"app.acme.example"},
		},
		{
			name: "CIDR under a target key passes through verbatim",
			args: map[string]any{"target": "10.0.2.0/24"},
			want: []string{"10.0.2.0/24"},
		},
		{
			name: "target list",
			args: map[string]any{"targets": []any{"10.0.2.15", "10.0.2.16"}},
			want: []string{"10.0.2.15", "10.0.2.16"},
		},
		{
			name: "nested object under a target key",
			args: map[string]any{"target": map[string]any{"host": "10.0.2.15", "ports": "22"}},
			want: []string{"10.0.2.15"},
		},
		{
			name: "non-target prose is not a destination",
			args: map[string]any{"scan_type": "syn", "timing": "aggressive", "ports": "22,80"},
			want: nil,
		},
		{
			name: "recipient is not an ip",
			args: map[string]any{"recipient": "bob@example.test"},
			want: nil,
		},
		{
			name: "fallback picks up an IP literal under an unknown key",
			args: map[string]any{"node": "10.0.2.15", "note": "be careful"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "fallback picks up an absolute URL under an unknown key",
			args: map[string]any{"resource": "http://10.0.2.15:8080/x"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "target key wins over fallback",
			args: map[string]any{"target": "10.0.2.15", "ports": "22", "note": "scan 10.0.2.99"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "empty target value is dropped",
			args: map[string]any{"target": ""},
			want: nil,
		},
		{
			name: "duplicates collapse",
			args: map[string]any{"target": "10.0.2.15", "host": "10.0.2.15"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "user@host:port loses user and port",
			args: map[string]any{"target": "root@10.0.2.15:22"},
			want: []string{"10.0.2.15"},
		},
		{
			name: "no arguments yields no targets",
			args: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := addrs(mcpScopeTargets(tt.args))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mcpScopeTargets(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestMCPScopeTargetsAreOrderIndependent(t *testing.T) {
	// A call's targets must not depend on Go's map iteration order: every
	// target-named value is collected, in a stable key-sorted order.
	args := map[string]any{"target": "10.0.2.15", "host": "10.0.2.16", "url": "http://10.0.2.17/"}
	want := []string{"10.0.2.16", "10.0.2.15", "10.0.2.17"} // host, target, url
	for i := 0; i < 50; i++ {
		if got := addrs(mcpScopeTargets(args)); !reflect.DeepEqual(got, want) {
			t.Fatalf("mcpScopeTargets() = %v, want %v (iteration %d)", got, want, i)
		}
	}
}

func TestMCPToolCarriesTargets(t *testing.T) {
	// The adapter must set Targets, or the policy engine never scope-checks
	// an MCP call (§5.5).
	tool := MCPTool(MCPToolSource{
		Name: "mcp__nmap__scan-ports",
		Call: func(context.Context, map[string]any) (string, error) { return "", nil },
	})
	if tool.Targets == nil {
		t.Fatal("MCPTool did not set Targets; MCP calls would bypass the scope check")
	}
	got := addrs(tool.Targets(map[string]any{"target": "10.0.2.15", "ports": "8080"}))
	if !reflect.DeepEqual(got, []string{"10.0.2.15"}) {
		t.Errorf("Targets() = %v, want the call's target", got)
	}
}

func TestMCPToolTargetsOverride(t *testing.T) {
	// An explicit Targets function wins over the default derivation.
	called := false
	tool := MCPTool(MCPToolSource{
		Name: "mcp__x__y",
		Call: func(context.Context, map[string]any) (string, error) { return "", nil },
		Targets: func(map[string]any) []policy.Target {
			called = true
			return []policy.Target{{Addr: "203.0.113.9"}}
		},
	})
	got := addrs(tool.Targets(map[string]any{"target": "10.0.2.15"}))
	if !called || !reflect.DeepEqual(got, []string{"203.0.113.9"}) {
		t.Errorf("override Targets = %v (called=%v), want the override to be used", got, called)
	}
}

func TestSplitNameTokens(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"target", []string{"target"}},
		{"targetHost", []string{"target", "host"}},
		{"ip_address", []string{"ip", "address"}},
		{"IPAddress", []string{"ip", "address"}},
		{"recipient", []string{"recipient"}},
		{"target-ip", []string{"target", "ip"}},
	}
	for _, tt := range tests {
		if got := splitNameTokens(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitNameTokens(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
