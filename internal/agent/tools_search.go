package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Search bounds. Both tools cap their result set so a repo-wide query cannot
// flood the context.
const (
	defaultGlobLimit = 200
	maxGlobLimit     = 2000
	defaultGrepLimit = 100
	maxGrepLimit     = 2000
	// maxGrepFileBytes is the largest file grep reads. Bigger files are
	// skipped rather than slurped.
	maxGrepFileBytes = 2 << 20 // 2 MiB
)

const globSchema = `{
  "type": "object",
  "properties": {
    "pattern": {
      "type": "string",
      "description": "Glob pattern to match against workspace-relative paths, e.g. \"*.go\" or \"internal/**/*_test.go\". A pattern without a slash also matches any file's base name."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum number of paths to return. Use 0 for the default (200)."
    }
  },
  "required": ["pattern", "limit"],
  "additionalProperties": false
}`

const grepSchema = `{
  "type": "object",
  "properties": {
    "pattern": {
      "type": "string",
      "description": "Go regular expression matched against each line."
    },
    "path": {
      "type": "string",
      "description": "File or directory to search, relative to the workspace root. Use \".\" for the whole workspace."
    },
    "glob": {
      "type": "string",
      "description": "Only search files whose workspace-relative path matches this glob, e.g. \"*.go\". Use \"\" to search every file."
    },
    "limit": {
      "type": "integer",
      "description": "Maximum number of matching lines to return. Use 0 for the default (100)."
    }
  },
  "required": ["pattern", "path", "glob", "limit"],
  "additionalProperties": false
}`

// GlobTool is the §5.1 glob orientation tool. It walks the workspace and
// returns matching relative paths, sorted.
func GlobTool(workspace string) Tool {
	root := absWorkspace(workspace)
	return Tool{
		Name:        "glob",
		Description: "Find files in the session workspace by glob pattern. Returns matching workspace-relative paths, one per line.",
		Parameters:  json.RawMessage(globSchema),
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			pattern, err := stringArg(args, "pattern")
			if err != nil {
				return "", err
			}
			if strings.TrimSpace(pattern) == "" {
				return "", fmt.Errorf("pattern is required")
			}
			limit, err := intArg(args, "limit", defaultGlobLimit, maxGlobLimit)
			if err != nil {
				return "", err
			}

			var matches []string
			_ = walkWorkspace(root, func(rel, _ string) {
				if matchWorkspaceGlob(pattern, rel) {
					matches = append(matches, rel)
				}
			})
			sort.Strings(matches)

			if len(matches) == 0 {
				return fmt.Sprintf("no files match %q", pattern), nil
			}
			truncated := false
			if len(matches) > limit {
				matches = matches[:limit]
				truncated = true
			}
			out := strings.Join(matches, "\n")
			if truncated {
				out += fmt.Sprintf("\n[glob: showing the first %d matches]", limit)
			}
			return out, nil
		},
	}
}

// GrepTool is the §5.1 grep orientation tool. It searches file contents for a
// regular expression and returns `path:line: text` matches.
func GrepTool(workspace string) Tool {
	root := absWorkspace(workspace)
	return Tool{
		Name:        "grep",
		Description: "Search file contents in the session workspace with a regular expression. Returns matches as `path:line: text`, one per line.",
		Parameters:  json.RawMessage(grepSchema),
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			pattern, err := stringArg(args, "pattern")
			if err != nil {
				return "", err
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return "", fmt.Errorf("invalid regular expression: %w", err)
			}
			start, err := optionalStringArg(args, "path", ".")
			if err != nil {
				return "", err
			}
			startAbs, err := resolveWithin(root, start)
			if err != nil {
				return "", err
			}
			fileGlob, err := optionalStringArg(args, "glob", "")
			if err != nil {
				return "", err
			}
			limit, err := intArg(args, "limit", defaultGrepLimit, maxGrepLimit)
			if err != nil {
				return "", err
			}

			var matches []string
			truncated := false
			visit := func(abs string) {
				if truncated {
					return
				}
				rel := displayPath(root, abs)
				if fileGlob != "" && !matchWorkspaceGlob(fileGlob, rel) {
					return
				}
				found := grepFile(abs, rel, re, limit-len(matches))
				matches = append(matches, found...)
				if len(matches) >= limit {
					truncated = true
				}
			}

			info, statErr := os.Stat(startAbs)
			switch {
			case statErr != nil:
				return "", fmt.Errorf("path %q: %w", start, statErr)
			case info.IsDir():
				_ = walkWorkspace(startAbs, func(_, abs string) { visit(abs) })
			case info.Mode().IsRegular():
				visit(startAbs)
			default:
				return "", fmt.Errorf("path %q is not a regular file or directory", start)
			}

			if len(matches) == 0 {
				return fmt.Sprintf("no matches for %q", pattern), nil
			}
			out := strings.Join(matches, "\n")
			if truncated {
				out += fmt.Sprintf("\n[grep: stopped at the %d-match limit]", limit)
			}
			return out, nil
		},
	}
}

// grepFile returns one match line per matching line in a file, up to limit.
// Binary and oversized files are skipped silently.
func grepFile(abs, rel string, re *regexp.Regexp, limit int) []string {
	if limit <= 0 {
		return nil
	}
	data, err := readMaybeLarge(abs)
	if err != nil || isBinary(data) {
		return nil
	}
	var out []string
	for i, line := range bytes.Split(data, []byte("\n")) {
		if re.Match(line) {
			out = append(out, fmt.Sprintf("%s:%d: %s", rel, i+1, strings.TrimRight(string(line), "\r")))
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

// readMaybeLarge reads a regular file up to maxGrepFileBytes.
func readMaybeLarge(abs string) ([]byte, error) {
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxGrepFileBytes {
		return nil, fmt.Errorf("skipped")
	}
	//nolint:gosec // the path was confined to the workspace by the caller.
	return os.ReadFile(abs)
}

// isBinary reports whether a file looks binary: a NUL byte in its first 8 KiB.
func isBinary(data []byte) bool {
	if len(data) > 8<<10 {
		data = data[:8<<10]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// walkWorkspace visits every regular file under root, emitting
// workspace-relative and absolute paths. VCS and dependency directories are
// skipped; unreadable entries are skipped rather than failing the walk.
func walkWorkspace(root string, fn func(rel, abs string)) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if d.IsDir() {
			if p != root && (d.Name() == ".git" || d.Name() == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		fn(filepath.ToSlash(rel), p)
		return nil
	})
}

// matchWorkspaceGlob matches a slash-separated relative path against a glob.
// `*` does not cross a path separator; a pattern without a slash also matches
// any base name; a leading `**/` matches at any depth.
func matchWorkspaceGlob(pattern, rel string) bool {
	if ok, _ := path.Match(pattern, rel); ok {
		return true
	}
	if ok, _ := path.Match(pattern, path.Base(rel)); ok {
		return true
	}
	if rest, found := strings.CutPrefix(pattern, "**/"); found {
		if ok, _ := path.Match(rest, rel); ok {
			return true
		}
		if ok, _ := path.Match(rest, path.Base(rel)); ok {
			return true
		}
	}
	return false
}

// absWorkspace resolves a workspace path, falling back to the input when it
// cannot be made absolute.
func absWorkspace(workspace string) string {
	root, err := filepath.Abs(workspace)
	if err != nil {
		return workspace
	}
	return root
}

// displayPath renders a path relative to the workspace root with forward
// slashes, falling back to the absolute path for anything outside it.
func displayPath(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}
