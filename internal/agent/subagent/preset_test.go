package subagent

import (
	"reflect"
	"slices"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/agent"
)

func TestPresetsMatchSpec(t *testing.T) {
	cases := []struct {
		name            string
		tools           []string
		network         Network
		engagementGated bool
	}{
		// Every preset also receives the engagement-state tools (§5.4 of the
		// spec): parsers run inside subagents, so the write path must reach
		// them.
		{"coder", append([]string{"read_file", "write_file", "edit_file", "glob", "grep", "bash", "code_exec"}, stateTools...), NetworkNone, false},
		{"recon", append([]string{"web_fetch", "bash", "read_file", "glob", "grep"}, stateTools...), NetworkScope, false},
		{"exploit-dev", append([]string{"bash", "code_exec", "read_file", "write_file", "edit_file", "glob", "grep", "web_fetch"}, stateTools...), NetworkScope, true},
		{"log-triage", append([]string{"read_file", "glob", "grep", "code_exec"}, stateTools...), NetworkNone, false},
	}
	if len(Presets()) != len(cases) {
		t.Fatalf("built-in presets = %d, want %d", len(Presets()), len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := Lookup(tc.name)
			if !ok {
				t.Fatalf("preset %q is not registered", tc.name)
			}
			if !reflect.DeepEqual(p.Tools, tc.tools) {
				t.Errorf("tools = %v, want %v", p.Tools, tc.tools)
			}
			if p.Network != tc.network {
				t.Errorf("network = %q, want %q", p.Network, tc.network)
			}
			if p.EngagementGated != tc.engagementGated {
				t.Errorf("engagementGated = %v, want %v", p.EngagementGated, tc.engagementGated)
			}
			if p.MaxTurns != DefaultMaxTurns || DefaultMaxTurns != 40 {
				t.Errorf("max turns = %d, want the spec's 40", p.MaxTurns)
			}
			if p.SystemPrompt() == "" {
				t.Error("system prompt is empty")
			}
			for _, tool := range stateTools {
				if !slices.Contains(p.Allowlist(), tool) {
					t.Errorf("preset %q is missing the engagement-state tool %q", p.Name, tool)
				}
			}
		})
	}
}

func TestNetworklessPresetsHaveNoNetworkTools(t *testing.T) {
	for _, p := range Presets() {
		if p.Network != NetworkNone {
			continue
		}
		for _, tool := range p.Allowlist() {
			if networkTools[tool] {
				t.Errorf("preset %q is classified %q but carries network tool %q", p.Name, NetworkNone, tool)
			}
		}
	}
}

func TestNoPresetReceivesDispatchSubagent(t *testing.T) {
	for _, p := range Presets() {
		for _, tool := range p.Allowlist() {
			if tool == agent.DispatchSubagentToolName {
				t.Errorf("preset %q exposes %s; one nesting level is structural", p.Name, agent.DispatchSubagentToolName)
			}
		}
	}

	// Even a hand-built preset that lists the delegation tool is sanitized:
	// the allowlist, not the model, enforces the nesting bound.
	handBuilt := Preset{Name: "rogue", Tools: []string{"read_file", agent.DispatchSubagentToolName}}
	if got := handBuilt.Allowlist(); len(got) != 1 || got[0] != "read_file" {
		t.Errorf("Allowlist() = %v, want the delegation tool stripped", got)
	}
}

func TestLookupUnknownRole(t *testing.T) {
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup(nope) reported a preset")
	}
}
