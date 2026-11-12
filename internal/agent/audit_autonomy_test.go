package agent

import (
	"bytes"
	"context"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// TestAuditRecordsTheAutonomyLevel pins the trail's side of the level's
// visibility (docs/exploitation-phase.md §6): an exploit-class decision carries
// the autonomy level that governed it, and every other call carries none.
func TestAuditRecordsTheAutonomyLevel(t *testing.T) {
	cases := []struct {
		name     string
		level    policy.Autonomy
		exploit  bool
		wantAuto string
	}{
		{"exploit-class at auto", policy.AutonomyAuto, true, "auto"},
		{"exploit-class at prompt", policy.AutonomyPrompt, true, "prompt"},
		{"an ordinary call records no level", policy.AutonomyAuto, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := workspace(t, map[string]string{"main.go": "package main\n"})
			tool := ReadFileTool(dir)
			tool.ExploitClass = tc.exploit

			var auditBuf bytes.Buffer
			engine := mustEngine(t, policy.ModeSafe,
				policy.WithROE(&policy.ROE{ExploitAllowed: true, ExploitationAutonomy: tc.level}),
				policy.WithProjectRules([]policy.Rule{{Tool: "read_file", Action: policy.VerdictAllow, Source: "project"}}),
			)
			fake := fakemodel.New(fakemodel.WithTurns(
				fakemodel.ToolCalls(fakemodel.Call("call-1", "read_file", `{"path":"main.go"}`)),
				fakemodel.Text("done"),
			))
			loop := NewLoop(fake, mustRegistry(t, tool), engine, audit.NewWriter(&auditBuf), testSystemPrompt)

			if _, err := loop.Run(context.Background(), nil, "read it"); err != nil {
				t.Fatalf("Run() = %v, want nil", err)
			}
			records := auditRecords(t, &auditBuf)
			if len(records) != 1 {
				t.Fatalf("audit records = %d, want 1", len(records))
			}
			if records[0].Autonomy != tc.wantAuto {
				t.Errorf("audit autonomy = %q, want %q", records[0].Autonomy, tc.wantAuto)
			}
		})
	}
}
