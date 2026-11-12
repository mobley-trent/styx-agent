package policy

import (
	"testing"
	"time"
)

// TestExploitationAutonomyLadder is the gate ladder the design holds the
// implementation to (docs/exploitation-phase.md §11): the level widens exactly
// one verdict, and every other rule still binds first.
func TestExploitationAutonomyLadder(t *testing.T) {
	inScope := fakeScope{inScopeHost: true}
	window := &TimeWindow{Start: "08:00", End: "18:00", TZ: "UTC"}
	noon := func() time.Time {
		return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	}

	tests := []struct {
		name    string
		roe     *ROE
		call    Call
		now     func() time.Time
		want    Verdict
		wantRsn Reason
	}{
		{
			name:    "prompt level holds an in-scope exploit for approval",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyPrompt},
			call:    exploitCall(inScopeHost),
			want:    VerdictPrompt,
			wantRsn: ReasonExploitApproval,
		},
		{
			name:    "absent level is the restrictive one",
			roe:     &ROE{ExploitAllowed: true},
			call:    exploitCall(inScopeHost),
			want:    VerdictPrompt,
			wantRsn: ReasonExploitApproval,
		},
		{
			name:    "auto approves an in-scope non-destructive exploit",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyAuto},
			call:    exploitCall(inScopeHost),
			want:    VerdictAllow,
			wantRsn: ReasonInScope,
		},
		{
			name:    "auto still cannot lift exploit_allowed false",
			roe:     &ROE{ExploitAllowed: false, ExploitationAutonomy: AutonomyAuto},
			call:    exploitCall(inScopeHost),
			want:    VerdictDeny,
			wantRsn: ReasonROE,
		},
		{
			name:    "auto still prompts out of scope",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyAuto},
			call:    exploitCall(outScopeHost),
			want:    VerdictPrompt,
			wantRsn: ReasonOutOfScope,
		},
		{
			name:    "auto still refuses a destructive-tagged exploit",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyAuto},
			call:    Call{Tool: "mcp__msf__run", ExploitClass: true, Destructive: true, ScopeTargets: []Target{{Addr: inScopeHost}}},
			want:    VerdictPrompt,
			wantRsn: ReasonDestructive,
		},
		{
			name:    "auto still refuses outside the time window",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyAuto, TimeWindow: window},
			call:    exploitCall(inScopeHost),
			now:     func() time.Time { return time.Date(2026, 10, 5, 23, 0, 0, 0, time.UTC) },
			want:    VerdictDeny,
			wantRsn: ReasonROE,
		},
		{
			name:    "auto inside the window approves",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyAuto, TimeWindow: window},
			call:    exploitCall(inScopeHost),
			now:     noon,
			want:    VerdictAllow,
			wantRsn: ReasonInScope,
		},
		{
			name:    "an ordinary in-scope call is unaffected at prompt",
			roe:     &ROE{ExploitAllowed: true, ExploitationAutonomy: AutonomyPrompt},
			call:    netCall(inScopeHost),
			want:    VerdictAllow,
			wantRsn: ReasonInScope,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{WithScope(inScope), WithROE(tt.roe)}
			if tt.now != nil {
				opts = append(opts, WithClock(tt.now))
			}
			engine, err := NewEngine(ModeEngagement, opts...)
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Decide(tt.call)
			if got.Verdict != tt.want || got.Reason != tt.wantRsn {
				t.Errorf("Decide() = %v/%s, want %v/%s", got.Verdict, got.Reason, tt.want, tt.wantRsn)
			}
			if engine.Autonomy() != tt.roe.AutonomyLevel() {
				t.Errorf("Autonomy() = %q, want %q", engine.Autonomy(), tt.roe.AutonomyLevel())
			}
		})
	}
}

// TestAutonomyLevelIsPromptWithoutEngagement pins the nil path: no engagement
// widens nothing, and the audit-facing level reads prompt.
func TestAutonomyLevelIsPromptWithoutEngagement(t *testing.T) {
	var roe *ROE
	if got := roe.AutonomyLevel(); got != AutonomyPrompt {
		t.Errorf("nil ROE level = %q, want prompt", got)
	}
	engine, err := NewEngine(ModeSafe)
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Autonomy(); got != AutonomyPrompt {
		t.Errorf("safe-mode Autonomy() = %q, want prompt", got)
	}
}

// exploitCall is an exploit-class call carrying one concrete target: the shape
// a pack allowlist tags and the ROE gate binds.
func exploitCall(addr string) Call {
	return Call{Tool: "mcp__msf__run", ExploitClass: true, ScopeTargets: []Target{{Addr: addr}}}
}
