package engagement

import (
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// TestExploitationAutonomyIsOptionalAndDefaulted pins the one ROE key whose
// absence is safe: it defaults to prompt, while the other two flags still
// refuse to be omitted (docs/exploitation-phase.md §2).
func TestExploitationAutonomyIsOptionalAndDefaulted(t *testing.T) {
	eng, err := gate(t, baseFile)
	if err != nil {
		t.Fatalf("gate() = %v", err)
	}
	if got := eng.ROE().AutonomyLevel(); got != policy.AutonomyPrompt {
		t.Errorf("absent exploitation_autonomy = %q, want prompt", got)
	}
}

func TestExploitationAutonomyIsReadByName(t *testing.T) {
	for _, level := range []policy.Autonomy{policy.AutonomyPrompt, policy.AutonomyAuto} {
		t.Run(string(level), func(t *testing.T) {
			src := replaceLine(baseFile, "  destructive_forbidden: true",
				"  destructive_forbidden: true\n  exploitation_autonomy: "+string(level))
			eng, err := gate(t, src)
			if err != nil {
				t.Fatalf("gate() = %v", err)
			}
			if got := eng.ROE().AutonomyLevel(); got != level {
				t.Errorf("level = %q, want %q", got, level)
			}
		})
	}
}

func TestExploitationAutonomyRefusesUnknownValues(t *testing.T) {
	// A typo must never silently mean something else: the level widens a
	// verdict, so an unrecognised value refuses to start.
	src := replaceLine(baseFile, "  destructive_forbidden: true",
		"  destructive_forbidden: true\n  exploitation_autonomy: always")
	eng, err := gate(t, src)
	if err == nil {
		t.Fatalf("gate() accepted %q as a level", "always")
	}
	if !errors.Is(err, ErrROE) {
		t.Errorf("error = %v, want it to wrap ErrROE", err)
	}
	if eng != nil {
		t.Error("a refused file yielded an engagement")
	}
	for _, want := range []string{"exploitation_autonomy", "prompt", "auto"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name %q", err, want)
		}
	}
}
