package policy

import "testing"

func TestRuleTableResolvePrecedence(t *testing.T) {
	// deny > prompt > allow among matching rules, regardless of order (§6.1).
	tests := []struct {
		name  string
		rules []Rule
		call  Call
		def   Action
		want  Verdict
	}{
		{
			name: "deny beats allow",
			rules: []Rule{
				{Tool: "bash", Action: VerdictAllow},
				{Tool: "bash", Action: VerdictDeny},
			},
			call: Call{Tool: "bash"},
			def:  VerdictPrompt,
			want: VerdictDeny,
		},
		{
			name: "prompt beats allow",
			rules: []Rule{
				{Tool: "bash", Action: VerdictAllow},
				{Tool: "bash", Action: VerdictPrompt},
			},
			call: Call{Tool: "bash"},
			def:  VerdictAllow,
			want: VerdictPrompt,
		},
		{
			name: "deny beats prompt beats allow in any order",
			rules: []Rule{
				{Tool: "bash", Action: VerdictAllow},
				{Tool: "bash", ParamPtr: "command", Action: VerdictPrompt},
				{Tool: "bash", ParamPtr: "command", Action: VerdictDeny},
			},
			call: Call{Tool: "bash", Params: map[string]any{"command": "ls"}},
			def:  VerdictAllow,
			want: VerdictDeny,
		},
		{
			name:  "no match falls to default",
			rules: []Rule{{Tool: "bash", Action: VerdictDeny}},
			call:  Call{Tool: "web_fetch"},
			def:   VerdictPrompt,
			want:  VerdictPrompt,
		},
		{
			name:  "param glob mismatch means rule does not apply",
			rules: []Rule{{Tool: "bash", ParamPtr: "cwd", Action: VerdictDeny}},
			call:  Call{Tool: "bash", Params: map[string]any{"command": "ls"}},
			def:   VerdictAllow,
			want:  VerdictAllow,
		},
		{
			name:  "empty ParamPtr matches params and absence",
			rules: []Rule{{Tool: "web_fetch", Action: VerdictDeny}},
			call:  Call{Tool: "web_fetch"},
			def:   VerdictAllow,
			want:  VerdictDeny,
		},
		{
			name:  "tool wildcard matches MCP-style names",
			rules: []Rule{{Tool: "mcp__*", Action: VerdictPrompt}},
			call:  Call{Tool: "mcp__nmap_scan"},
			def:   VerdictAllow,
			want:  VerdictPrompt,
		},
		{
			name:  "tool star matches anything",
			rules: []Rule{{Tool: "*", Action: VerdictDeny}},
			call:  Call{Tool: "anything"},
			def:   VerdictAllow,
			want:  VerdictDeny,
		},
		{
			name:  "allow matches only the allow rule",
			rules: []Rule{{Tool: "bash", Action: VerdictAllow}},
			call:  Call{Tool: "bash"},
			def:   VerdictPrompt,
			want:  VerdictAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := &RuleTable{Rules: tt.rules}
			got := table.resolve(tt.call, tt.def)
			if got.Verdict != tt.want {
				t.Errorf("resolve() = %v (%s), want %v", got.Verdict, got.Reason, tt.want)
			}
			if got.Verdict == tt.def && tt.want == tt.def && len(tt.rules) > 0 {
				if got.Reason != ReasonDefaultTable {
					t.Errorf("resolve() reason = %s, want default-table when nothing matched", got.Reason)
				}
			}
		})
	}
}

func TestDefaultRules(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		tool string
		want Verdict
	}{
		// Safe mode: permissive reads, guarded writes/exec/network (§6.2).
		{name: "safe: read_file allows", mode: ModeSafe, tool: "read_file", want: VerdictAllow},
		{name: "safe: glob allows", mode: ModeSafe, tool: "glob", want: VerdictAllow},
		{name: "safe: grep allows", mode: ModeSafe, tool: "grep", want: VerdictAllow},
		{name: "safe: write prompts", mode: ModeSafe, tool: "write_file", want: VerdictPrompt},
		{name: "safe: edit prompts", mode: ModeSafe, tool: "edit_file", want: VerdictPrompt},
		{name: "safe: bash prompts", mode: ModeSafe, tool: "bash", want: VerdictPrompt},
		{name: "safe: code_exec prompts", mode: ModeSafe, tool: "code_exec", want: VerdictPrompt},
		{name: "safe: web_fetch prompts", mode: ModeSafe, tool: "web_fetch", want: VerdictPrompt},
		{name: "safe: ssh_logs prompts", mode: ModeSafe, tool: "ssh_logs", want: VerdictPrompt},
		{name: "safe: subagent dispatch prompts", mode: ModeSafe, tool: "dispatch_subagent", want: VerdictPrompt},
		{name: "safe: skill allows", mode: ModeSafe, tool: "skill", want: VerdictAllow},
		{name: "safe: unknown tool falls to default prompt", mode: ModeSafe, tool: "mcp__unknown", want: VerdictPrompt},

		// Engagement defaults are identical: the mode flag alone widens
		// nothing (§6.2); only scope matches widen.
		{name: "engagement: write still prompts", mode: ModeEngagement, tool: "write_file", want: VerdictPrompt},
		{name: "engagement: bash still prompts", mode: ModeEngagement, tool: "bash", want: VerdictPrompt},
		{name: "engagement: read still allows", mode: ModeEngagement, tool: "read_file", want: VerdictAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := DefaultRules(tt.mode)
			got := table.resolve(Call{Tool: tt.tool}, VerdictPrompt)
			if got.Verdict != tt.want {
				t.Errorf("DefaultRules(%s).resolve(%s) = %v, want %v", tt.mode, tt.tool, got.Verdict, tt.want)
			}
		})
	}

	// Both modes must produce identical tables: engagement widens nothing.
	safe := DefaultRules(ModeSafe)
	eng := DefaultRules(ModeEngagement)
	if len(safe.Rules) != len(eng.Rules) {
		t.Fatalf("default tables differ in length: safe=%d engagement=%d", len(safe.Rules), len(eng.Rules))
	}
	for i := range safe.Rules {
		if safe.Rules[i] != eng.Rules[i] {
			t.Errorf("default table rule %d differs between modes: %+v vs %+v", i, safe.Rules[i], eng.Rules[i])
		}
	}
}

func TestDefaultRulesUnknownModePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("DefaultRules(Mode(\"bogus\")) did not panic")
		}
	}()
	DefaultRules(Mode("bogus"))
}

func TestOverlay(t *testing.T) {
	base := DefaultRules(ModeSafe)
	project := []Rule{
		// Widen: allow prompt→allow for bash. The base table's bash rule
		// matches without params, so the overlay rule also matches without
		// params — equal precedence, later (project) rule wins the tie.
		{Tool: "bash", Action: VerdictAllow, Source: "project"},
		// Widen via param glob: read_file gains an allow rule for a specific
		// path shape (base already allows read_file; this asserts coexistence).
		{Tool: "read_file", ParamPtr: "path", Action: VerdictAllow, Source: "project"},
		// Narrow: deny a dangerous tool outright.
		{Tool: "ssh_logs", Action: VerdictDeny, Source: "project"},
	}
	merged := base.Overlay(project)
	// bash and ssh_logs rules replace their base counterparts by key
	// (project wins); the read_file param-glob rule appends.
	if merged.Len() != base.Len()+1 {
		t.Fatalf("overlay length = %d, want %d (2 replacements, 1 append)", merged.Len(), base.Len()+1)
	}

	tests := []struct {
		name string
		call Call
		want Verdict
	}{
		{name: "project widens bash to allow", call: Call{Tool: "bash", Params: map[string]any{"command": "go test ./..."}}, want: VerdictAllow},
		{name: "param-glob allow keeps read_file allowed", call: Call{Tool: "read_file", Params: map[string]any{"path": "src/main.go"}}, want: VerdictAllow},
		{name: "project narrows ssh_logs to deny", call: Call{Tool: "ssh_logs"}, want: VerdictDeny},
		{name: "untouched tool keeps default", call: Call{Tool: "write_file"}, want: VerdictPrompt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := merged.resolve(tt.call, VerdictPrompt)
			if got.Verdict != tt.want {
				t.Errorf("overlay resolve(%s) = %v, want %v", tt.call.Tool, got.Verdict, tt.want)
			}
		})
	}

	// Narrowing by param glob composes with widening by tool glob: with both
	// project rules present, the deny on bash/command out-ranks the
	// tool-level allow for any call carrying a command (deny > allow),
	// because resolution is precedence-based over all matching rules.
	narrowed := base.Overlay([]Rule{
		{Tool: "bash", Action: VerdictAllow, Source: "project"},
		{Tool: "bash", ParamPtr: "command", Action: VerdictDeny, Source: "project"},
	})
	if got := narrowed.resolve(Call{Tool: "bash", Params: map[string]any{"command": "rm -rf /"}}, VerdictPrompt); got.Verdict != VerdictDeny {
		t.Errorf("bash with command = %v, want deny (deny out-ranks allow)", got.Verdict)
	}

	// The base table must be untouched by merging (Overlay returns a copy).
	if got := base.resolve(Call{Tool: "ssh_logs"}, VerdictPrompt); got.Verdict != VerdictPrompt {
		t.Errorf("base table mutated by Overlay: ssh_logs = %v, want prompt", got.Verdict)
	}
	if got := base.resolve(Call{Tool: "bash", Params: map[string]any{"command": "ls"}}, VerdictPrompt); got.Verdict != VerdictPrompt {
		t.Errorf("base table mutated by Overlay: bash = %v, want prompt", got.Verdict)
	}
}

func TestGlobMatchTool(t *testing.T) {
	tests := []struct {
		pattern string
		tool    string
		want    bool
	}{
		{"bash", "bash", true},
		{"bash", "web_fetch", false},
		{"*", "bash", true},
		{"*", "", false},
		{"mcp__*", "mcp__nmap", true},
		{"mcp__*", "builtin", false},
		{"**", "a/b", true},
		{"**", "", true},
		{"a/**", "a", true},     // ** matches zero segments
		{"a/**/c", "a/c", true}, // zero segments in the middle
		{"a/**/c", "a/b/c", true},
		{"a/*", "a", false}, // * needs exactly one segment
		{"a/*", "a/b/c", false},
	}
	for _, tt := range tests {
		if got := globMatch(tt.pattern, tt.tool); got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.tool, got, tt.want)
		}
	}
}
