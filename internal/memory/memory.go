package memory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileName is the project memory file (§10.2). It lives at the repo root and
// is auto-loaded into the system prompt.
const FileName = "STYX.md"

// Path is the memory file's location for a project directory.
func Path(projectDir string) string { return filepath.Join(projectDir, FileName) }

// EngagementNotes is the structured record the harness appends to STYX.md when
// an engagement ends (§7.5, §10.2). Every field is harness-derived from the
// engagement file and the session's own records — the appender never invents
// findings on the model's behalf.
type EngagementNotes struct {
	// Name is the engagement file's label.
	Name string
	// Operator is the informational operator name from the file.
	Operator string
	// Targets is the authorization pool exactly as declared.
	Targets []string
	// ExploitAllowed mirrors roe.exploit_allowed.
	ExploitAllowed bool
	// DestructiveForbidden mirrors roe.destructive_forbidden.
	DestructiveForbidden bool
	// Expires is the rendered expiry, empty when evergreen.
	Expires string
	// Started is the activation timestamp, rendered RFC 3339.
	Started string
	// Ended is the deactivation timestamp, rendered RFC 3339.
	Ended string
	// Tools counts the session's admitted tool calls by name.
	Tools map[string]int
	// Artifacts lists the workspace paths the session wrote.
	Artifacts []string
}

// AppendEngagementNotes appends a timestamped, structured engagement-notes
// block to the project's STYX.md and returns the block written. The block is
// never silent and never model-invented: the harness assembles it from the
// engagement file and the session record. The existing file is preserved —
// the block is appended, never replacing memory the operator wrote.
func AppendEngagementNotes(projectDir string, notes EngagementNotes) (string, error) {
	path := Path(projectDir)
	existing, err := Load(projectDir)
	if err != nil {
		return "", err
	}

	existing = strings.TrimRight(existing, "\n")
	separator := ""
	if existing != "" {
		separator = "\n\n---\n\n"
	}
	block := renderEngagementNotes(notes)

	//nolint:gosec // the project directory is the operator's own checkout.
	if err := os.WriteFile(path, []byte(existing+separator+block), 0o600); err != nil {
		return "", fmt.Errorf("memory: append engagement notes to %s: %w", path, err)
	}
	return block, nil
}

// renderEngagementNotes renders one structured notes block. Empty fields are
// omitted, so a minimal engagement still produces a clean record.
func renderEngagementNotes(n EngagementNotes) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Engagement notes — %s\n\n", n.Ended)
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	if n.Name != "" {
		line("- engagement: %s", n.Name)
	}
	if n.Operator != "" {
		line("- operator: %s", n.Operator)
	}
	if len(n.Targets) > 0 {
		line("- targets: %s", strings.Join(n.Targets, ", "))
	}
	line("- rules of engagement: exploit_allowed=%t destructive_forbidden=%t", n.ExploitAllowed, n.DestructiveForbidden)
	if n.Expires != "" {
		line("- expires: %s", n.Expires)
	}
	if n.Started != "" {
		line("- activated: %s", n.Started)
	}
	if n.Ended != "" {
		line("- ended: %s", n.Ended)
	}
	if len(n.Tools) > 0 {
		names := make([]string, 0, len(n.Tools))
		for name := range n.Tools {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, fmt.Sprintf("%s×%d", name, n.Tools[name]))
		}
		line("- tool calls: %s", strings.Join(parts, ", "))
	}
	if len(n.Artifacts) > 0 {
		arts := append([]string(nil), n.Artifacts...)
		sort.Strings(arts)
		line("- artifacts: %s", strings.Join(arts, ", "))
	}
	return b.String()
}

// Load reads the project's STYX.md. Memory is optional: a missing file is the
// empty string, not an error. Anything else — an unreadable file, a directory
// where a file belongs — is reported, because silently dropping memory would
// hide an engagement note the operator expects the agent to see.
func Load(projectDir string) (string, error) {
	path := Path(projectDir)
	//nolint:gosec // the project directory is the operator's own checkout.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("memory: read %s: %w", path, err)
	}
	return string(data), nil
}
