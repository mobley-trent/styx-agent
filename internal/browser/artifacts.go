package browser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Artifact locations (§3.4, §5). Screenshots and downloads are evidence under
// `.styx/out/`, retained with the session's other artifacts; their bytes never
// enter model context.
const (
	// BrowserOutDir is the screenshot root.
	BrowserOutDir = ".styx/out/browser"
	// DownloadsOutDir is the download root.
	DownloadsOutDir = ".styx/out/downloads"
)

// Artifact is a written file: its path, size, and metadata. There is
// deliberately no bytes field (§3.4): no tool returns pixels or file contents.
type Artifact struct {
	// Path is the workspace-relative artifact path.
	Path string
	// Filename is the sanitized server-supplied download name, empty for a
	// screenshot.
	Filename string
	// ContentType is the reported content type, empty for a screenshot.
	ContentType string
	// Bytes is the artifact's size.
	Bytes int64
	// URL and Title describe the page the artifact came from.
	URL   string
	Title string
	// Width and Height are the viewport at capture time, for a screenshot.
	Width  int
	Height int
}

// ScreenshotDir is a session's screenshot directory:
// <project>/.styx/out/browser/<session>.
func ScreenshotDir(projectDir, session string) string {
	return filepath.Join(projectDir, BrowserOutDir, safeComponent(session))
}

// DownloadDir is a session's download directory:
// <project>/.styx/out/downloads/<session>.
func DownloadDir(projectDir, session string) string {
	return filepath.Join(projectDir, DownloadsOutDir, safeComponent(session))
}

// safeComponent reduces a session id to one path component.
func safeComponent(raw string) string {
	name := filepath.Base(strings.TrimSpace(raw))
	if name == "" || name == "." || name == ".." || name == string(filepath.Separator) {
		return "session"
	}
	return name
}

// NextScreenshotPath returns the first free `shot-<n>.png` in dir.
func NextScreenshotPath(dir string) (string, error) {
	//nolint:gosec // artifacts are model-visible output, readable like the rest of .styx.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("browser: create screenshot directory %s: %w", dir, err)
	}
	for n := 1; n <= 100000; n++ {
		path := filepath.Join(dir, fmt.Sprintf("shot-%d.png", n))
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return path, nil
		} else if err != nil {
			return "", fmt.Errorf("browser: inspect %s: %w", path, err)
		}
	}
	return "", fmt.Errorf("browser: %s has no free screenshot number", dir)
}

// WriteArtifact writes data to path atomically: a temp file in the same
// directory, then a rename. A screenshot or download that cannot be written is
// a tool error, never an announced artifact (§8).
func WriteArtifact(path string, data []byte) (int64, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return 0, fmt.Errorf("browser: create temp artifact in %s: %w", dir, err)
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return 0, fmt.Errorf("browser: write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("browser: close %s: %w", name, err)
	}
	//nolint:gosec // an artifact is handed to the model and the operator, not secret.
	if err := os.Chmod(name, 0o644); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("browser: set %s mode: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return 0, fmt.Errorf("browser: commit %s: %w", path, err)
	}
	return int64(len(data)), nil
}

// SanitizeDownloadName reduces a server-supplied filename to one safe basename
// (§3.4). It is a basename by construction, so a hostile name cannot escape the
// download directory; `..`, control characters, and leading dots are removed
// rather than passed through.
func SanitizeDownloadName(raw string) string {
	name := strings.ToValidUTF8(raw, "_")
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}

	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 0x20 || r == 0x7f:
			// Drop control characters, including NUL.
		case r == '/' || r == '\\':
			// Already split; a stray one never becomes a separator again.
		default:
			b.WriteRune(r)
		}
	}
	name = strings.TrimSpace(b.String())
	if name == "" || name == "." || name == ".." {
		return "download"
	}
	if strings.HasPrefix(name, ".") {
		// A dotfile is hidden, not safer: name it so the operator sees it.
		name = "file-" + strings.TrimLeft(name, ".")
		if name == "file-" {
			return "download"
		}
	}

	// Bound the name without losing its extension.
	const maxBase = 100
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if len(ext) > 32 {
		ext = ""
		base = name
	}
	if len(base) > maxBase {
		cut := maxBase
		for cut > 0 && !utf8Start(base[cut]) {
			cut--
		}
		base = base[:cut]
	}
	if base == "" {
		base = "download"
	}
	return base + ext
}

// UniquePath returns a path in dir that does not collide with an existing file:
// the sanitized name, or `name-2`, `name-3`, ... beside it.
func UniquePath(dir, name string) string {
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return path
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for n := 2; n <= 100000; n++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, n, ext))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
	return path
}
