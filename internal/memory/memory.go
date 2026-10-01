package memory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileName is the project memory file (§10.2). It lives at the repo root and
// is auto-loaded into the system prompt.
const FileName = "STYX.md"

// Path is the memory file's location for a project directory.
func Path(projectDir string) string { return filepath.Join(projectDir, FileName) }

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
