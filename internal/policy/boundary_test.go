package policy

import (
	"os/exec"
	"strings"
	"testing"
)

// packageImports returns the non-standard-library packages imported by this
// package (including its tests), via `go list -deps -f`. Used by the boundary
// test to mechanically enforce the §2 rule that policy imports nothing from
// tui, model, or agent.
func packageImports(t *testing.T) ([]string, error) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps",
		"github.com/mobley-trent/styx-agent/internal/policy")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var self []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, "github.com/mobley-trent/styx-agent/internal/") {
			self = append(self, strings.TrimSpace(line))
		}
	}
	return self, nil
}
