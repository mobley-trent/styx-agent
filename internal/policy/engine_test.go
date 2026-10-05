package policy

import "testing"

// fakeScope is a Scope fake: membership by exact address.
type fakeScope map[string]bool

func (f fakeScope) InScope(addr string) bool { return f[addr] }

const (
	inScopeHost  = "10.0.0.5"
	outScopeHost = "203.0.113.9"
)

// engagedROE is the ROE of a permissive engagement: exploitation allowed,
// nothing forbidden, no time window.
func engagedROE() *ROE { return &ROE{ExploitAllowed: true} }

// netCall is a network call to addr; execCall an exec with a command.
func netCall(addr string) Call {
	return Call{Tool: "web_fetch", ScopeTargets: []Target{{Addr: addr}}}
}
func execCall(cmd string) Call {
	return Call{Tool: "bash", Params: map[string]any{"command": cmd}}
}

func TestEngineSafeModeBasics(t *testing.T) {
	e, err := NewEngine(ModeSafe)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		call    Call
		want    Verdict
		wantRsn Reason
	}{
		{name: "read allowed", call: Call{Tool: "read_file"}, want: VerdictAllow, wantRsn: ReasonRuleMatch},
		{name: "write prompts", call: Call{Tool: "write_file"}, want: VerdictPrompt, wantRsn: ReasonRuleMatch},
		{name: "bash prompts", call: execCall("ls"), want: VerdictPrompt, wantRsn: ReasonRuleMatch},
		{name: "network prompts", call: netCall(inScopeHost), want: VerdictPrompt, wantRsn: ReasonRuleMatch},
		{name: "unknown tool defaults to prompt", call: Call{Tool: "mcp__unknown"}, want: VerdictPrompt, wantRsn: ReasonDefaultTable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.Decide(tt.call)
			if got.Verdict != tt.want || got.Reason != tt.wantRsn {
				t.Errorf("Decide() = %v/%s, want %v/%s", got.Verdict, got.Reason, tt.want, tt.wantRsn)
			}
		})
	}
}

func TestEngineEngagementScopeSemantics(t *testing.T) {
	scope := fakeScope{inScopeHost: true}
	tests := []struct {
		name    string
		mode    Mode
		scope   Scope
		call    Call
		want    Verdict
		wantRsn Reason
	}{
		{
			name: "engagement in-scope network auto-allows",
			mode: ModeEngagement, scope: scope, call: netCall(inScopeHost),
			want: VerdictAllow, wantRsn: ReasonInScope,
		},
		{
			name: "engagement out-of-scope prompts",
			mode: ModeEngagement, scope: scope, call: netCall(outScopeHost),
			want: VerdictPrompt, wantRsn: ReasonOutOfScope,
		},
		{
			name: "safe mode never auto-allows network even in-scope target",
			mode: ModeSafe, scope: scope, call: netCall(inScopeHost),
			want: VerdictPrompt, wantRsn: ReasonRuleMatch,
		},
		{
			name: "engagement mode flag alone widens nothing (no targets)",
			mode: ModeEngagement, scope: scope, call: Call{Tool: "write_file"},
			want: VerdictPrompt, wantRsn: ReasonRuleMatch,
		},
		{
			name: "engagement with nil scope falls back to table",
			mode: ModeEngagement, scope: nil, call: netCall(inScopeHost),
			want: VerdictPrompt, wantRsn: ReasonRuleMatch,
		},
		{
			name: "engagement in-scope read still resolves via table",
			mode: ModeEngagement, scope: scope, call: Call{Tool: "read_file"},
			want: VerdictAllow, wantRsn: ReasonRuleMatch,
		},
		{
			name: "any out-of-scope target in a multi-target call prompts",
			mode: ModeEngagement, scope: scope,
			call: Call{Tool: "web_fetch", ScopeTargets: []Target{{Addr: inScopeHost}, {Addr: outScopeHost}}},
			want: VerdictPrompt, wantRsn: ReasonOutOfScope,
		},
		{
			name: "destructive in-scope call prompts, never auto-allows",
			mode: ModeEngagement, scope: scope,
			call: Call{Tool: "mcp__cuckoo__detonate", Destructive: true, ScopeTargets: []Target{{Addr: inScopeHost}}},
			want: VerdictPrompt, wantRsn: ReasonDestructive,
		},
		{
			name: "non-destructive in-scope call still auto-allows",
			mode: ModeEngagement, scope: scope,
			call: Call{Tool: "mcp__ghidra__decompile", ScopeTargets: []Target{{Addr: inScopeHost}}},
			want: VerdictAllow, wantRsn: ReasonInScope,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEngine(tt.mode, WithScope(tt.scope), WithROE(engagedROE()))
			if err != nil {
				t.Fatal(err)
			}
			got := e.Decide(tt.call)
			if got.Verdict != tt.want || got.Reason != tt.wantRsn {
				t.Errorf("Decide() = %v/%s, want %v/%s", got.Verdict, got.Reason, tt.want, tt.wantRsn)
			}
		})
	}
}

func TestEngineROEvsScope(t *testing.T) {
	// The distinction the whole ticket turns on: ROE violations hard-deny
	// regardless of scope or promptability; out-of-scope merely prompts.
	scope := fakeScope{inScopeHost: true}
	roe := &ROE{ExploitAllowed: false, DestructiveForbidden: true}

	tests := []struct {
		name string
		call Call
		want Verdict
	}{
		{name: "in-scope exploit still hard-denies", call: Call{Tool: "exploit_payload", ExploitClass: true, ScopeTargets: []Target{{Addr: inScopeHost}}}, want: VerdictDeny},
		{name: "out-of-scope exploit hard-denies (never prompts)", call: Call{Tool: "exploit_payload", ExploitClass: true, ScopeTargets: []Target{{Addr: outScopeHost}}}, want: VerdictDeny},
		{name: "destructive in-scope hard-denies", call: Call{Tool: "bash", Params: map[string]any{"command": "rm -rf /"}, Destructive: true, ScopeTargets: []Target{{Addr: inScopeHost}}}, want: VerdictDeny},
		{name: "non-violating out-of-scope call prompts", call: netCall(outScopeHost), want: VerdictPrompt},
		{name: "non-violating in-scope call allows", call: netCall(inScopeHost), want: VerdictAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEngine(ModeEngagement, WithScope(scope), WithROE(roe))
			if err != nil {
				t.Fatal(err)
			}
			got := e.Decide(tt.call)
			if got.Verdict != tt.want {
				t.Errorf("Decide() = %v/%s, want %v", got.Verdict, got.Reason, tt.want)
			}
			if got.Verdict == VerdictDeny && got.Reason != ReasonROE {
				t.Errorf("ROE deny reason = %s, want %s", got.Reason, ReasonROE)
			}
		})
	}
}

func TestEngineRuleNarrowingOverridesScope(t *testing.T) {
	// A project deny rule binds even in engagement mode against an in-scope
	// target (project rules may narrow defaults; scope never overrides the
	// table's deny).
	scope := fakeScope{inScopeHost: true}
	e, err := NewEngine(ModeEngagement,
		WithScope(scope), WithROE(engagedROE()),
		WithProjectRules([]Rule{
			{Tool: "web_fetch", Action: VerdictDeny, Source: "project"},
		}))
	if err != nil {
		t.Fatal(err)
	}
	got := e.Decide(netCall(inScopeHost))
	if got.Verdict != VerdictDeny || got.Reason != ReasonRuleMatch {
		t.Errorf("Decide() = %v/%s, want deny/rule-match", got.Verdict, got.Reason)
	}

	// A project prompt narrows an in-scope auto-allow to a prompt.
	ep, err := NewEngine(ModeEngagement,
		WithScope(scope), WithROE(engagedROE()),
		WithProjectRules([]Rule{
			{Tool: "web_fetch", Action: VerdictPrompt, Source: "project"},
		}))
	if err != nil {
		t.Fatal(err)
	}
	if got := ep.Decide(netCall(inScopeHost)); got.Verdict != VerdictPrompt || got.Reason != ReasonRuleMatch {
		t.Errorf("prompted web_fetch = %v/%s, want prompt/rule-match", got.Verdict, got.Reason)
	}

	// A project rule may also widen prompts to allows in safe mode (§6.1).
	ew, err := NewEngine(ModeSafe, WithProjectRules([]Rule{
		{Tool: "write_file", Action: VerdictAllow, Source: "project"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := ew.Decide(Call{Tool: "write_file"}); got.Verdict != VerdictAllow {
		t.Errorf("widened write_file = %v/%s, want allow", got.Verdict, got.Reason)
	}

	// But a project allow never widens a scope check: out-of-scope prompts
	// even under a project allow (§6.1).
	eo, err := NewEngine(ModeEngagement,
		WithScope(scope), WithROE(engagedROE()),
		WithProjectRules([]Rule{
			{Tool: "web_fetch", Action: VerdictAllow, Source: "project"},
		}))
	if err != nil {
		t.Fatal(err)
	}
	if got := eo.Decide(netCall(outScopeHost)); got.Verdict != VerdictPrompt || got.Reason != ReasonOutOfScope {
		t.Errorf("project-allow out-of-scope = %v/%s, want prompt/out-of-scope", got.Verdict, got.Reason)
	}
}

func TestEngineTimeWindowViaInjectedClock(t *testing.T) {
	// The injected clock drives time_window; the file's timezone is honored
	// by evaluating wall-clock in the window's location. Each engine is
	// built with its own clock — engines are immutable after construction.
	scope := fakeScope{inScopeHost: true}
	roe := &ROE{
		ExploitAllowed: true,
		TimeWindow:     &TimeWindow{Start: "08:00", End: "18:00", TZ: "America/New_York"},
	}

	noon, err := NewEngine(ModeEngagement, WithScope(scope), WithROE(roe),
		WithClock(fixedClock(t, "2026-09-29T12:00:00-04:00")))
	if err != nil {
		t.Fatal(err)
	}
	night, err := NewEngine(ModeEngagement, WithScope(scope), WithROE(roe),
		WithClock(fixedClock(t, "2026-09-29T23:00:00-04:00")))
	if err != nil {
		t.Fatal(err)
	}

	if got := noon.Decide(netCall(inScopeHost)); got.Verdict != VerdictAllow {
		t.Errorf("in-window in-scope call = %v/%s, want allow", got.Verdict, got.Reason)
	}

	got := night.Decide(netCall(inScopeHost))
	if got.Verdict != VerdictDeny || got.Reason != ReasonROE {
		t.Errorf("out-of-window in-scope call = %v/%s, want deny/roe", got.Verdict, got.Reason)
	}

	// ROE deny out-ranks scope even for out-of-scope targets: no prompt.
	got = night.Decide(netCall(outScopeHost))
	if got.Verdict != VerdictDeny || got.Reason != ReasonROE {
		t.Errorf("out-of-window out-of-scope call = %v/%s, want deny/roe (never prompt)", got.Verdict, got.Reason)
	}
}

func TestEngineDestructiveNeverAutoAllowed(t *testing.T) {
	// A project allow rule widens a prompt to an allow, but it must never
	// auto-allow a destructive-tagged call: detonation is always an explicit
	// operator decision (§8.3).
	e, err := NewEngine(ModeSafe, WithProjectRules([]Rule{
		{Tool: "code_exec", Action: VerdictAllow, Source: "project"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"lang": "python", "code": "print(1)"}

	got := e.Decide(Call{Tool: "code_exec", Params: params, Destructive: true})
	if got.Verdict != VerdictPrompt || got.Reason != ReasonDestructive {
		t.Errorf("destructive call under a project allow = %v/%s, want prompt/%s", got.Verdict, got.Reason, ReasonDestructive)
	}
	// The same call without the tag still resolves through the widened rule.
	if got := e.Decide(Call{Tool: "code_exec", Params: params}); got.Verdict != VerdictAllow {
		t.Errorf("non-destructive call under a project allow = %v/%s, want allow", got.Verdict, got.Reason)
	}
}

func TestNewEngineValidation(t *testing.T) {
	if _, err := NewEngine(Mode("bogus")); err == nil {
		t.Errorf("NewEngine(bogus mode) = nil error, want error")
	}
	e, err := NewEngine(ModeSafe)
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode() != ModeSafe {
		t.Errorf("Mode() = %s, want safe", e.Mode())
	}
	// Nil table falls back to the mode defaults.
	if got := e.Decide(Call{Tool: "read_file"}); got.Verdict != VerdictAllow {
		t.Errorf("default-table engine read_file = %v, want allow", got.Verdict)
	}
}

// TestPolicyPackageImportsNothingForbidden is the mechanical boundary check
// (acceptance: "imports nothing from the TUI, model, or agent packages").
// It runs `go list` on the package and fails if any forbidden internal
// package appears in the import graph; the compile-level guarantee (an
// import would be an undeclared dependency) backs it up.
func TestPolicyPackageImportsNothingForbidden(t *testing.T) {
	imports, err := packageImports(t)
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, imp := range imports {
		for _, bad := range []string{
			"github.com/mobley-trent/styx-agent/internal/tui",
			"github.com/mobley-trent/styx-agent/internal/model",
			"github.com/mobley-trent/styx-agent/internal/agent",
			"github.com/mobley-trent/styx-agent/internal/agent/subagent",
		} {
			if imp == bad {
				t.Errorf("policy package imports forbidden package %q", imp)
			}
		}
	}
}
