package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/diff"
)

const writeFileSchema = `{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Path to the file to write, absolute or relative to the workspace root."
    },
    "content": {
      "type": "string",
      "description": "The file's complete new contents."
    }
  },
  "required": ["path", "content"],
  "additionalProperties": false
}`

const editFileSchema = `{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Path to the file to edit, absolute or relative to the workspace root."
    },
    "old_string": {
      "type": "string",
      "description": "The exact text to replace. Must be unique unless replace_all is true."
    },
    "new_string": {
      "type": "string",
      "description": "The replacement text."
    },
    "replace_all": {
      "type": "boolean",
      "description": "Replace every occurrence of old_string instead of requiring it to be unique."
    }
  },
  "required": ["path", "old_string", "new_string", "replace_all"],
  "additionalProperties": false
}`

// WriteFileTool is the §5.1 write_file tool. It is diff-class (§9.2): its
// Preview computes the change for review, and its Handler is the apply step
// the loop calls only after the operator accepts.
func WriteFileTool(workspace string) Tool {
	root := absWorkspace(workspace)
	return Tool{
		Name:        "write_file",
		Description: "Write the complete contents of a file in the session workspace, creating it if needed.",
		Parameters:  json.RawMessage(writeFileSchema),
		Preview: func(args map[string]any) (*diff.FileDiff, error) {
			path, err := stringArg(args, "path")
			if err != nil {
				return nil, err
			}
			content, err := stringArg(args, "content")
			if err != nil {
				return nil, err
			}
			abs, err := resolveWithin(root, path)
			if err != nil {
				return nil, err
			}
			old, err := readExisting(abs)
			if err != nil {
				return nil, err
			}
			return diff.File(displayPath(root, abs), old, content), nil
		},
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			path, err := stringArg(args, "path")
			if err != nil {
				return "", err
			}
			content, err := stringArg(args, "content")
			if err != nil {
				return "", err
			}
			abs, err := resolveWithin(root, path)
			if err != nil {
				return "", err
			}
			if info, statErr := os.Stat(abs); statErr == nil && info.IsDir() {
				return "", fmt.Errorf("%s is a directory, not a file", displayPath(root, abs))
			}
			if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
				return "", fmt.Errorf("create directory for %s: %w", path, err)
			}
			//nolint:gosec // the path was resolved and confined to the workspace above.
			if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
				return "", fmt.Errorf("write %s: %w", path, err)
			}
			return fmt.Sprintf("wrote %s (%s)", displayPath(root, abs), lineCount(content)), nil
		},
	}
}

// EditFileTool is the §5.1 edit_file tool: a targeted string replacement. It is
// diff-class like write_file.
func EditFileTool(workspace string) Tool {
	root := absWorkspace(workspace)
	edit := func(args map[string]any) (abs, rel, updated string, replacements int, err error) {
		path, err := stringArg(args, "path")
		if err != nil {
			return "", "", "", 0, err
		}
		oldString, err := stringArg(args, "old_string")
		if err != nil {
			return "", "", "", 0, err
		}
		newString, err := stringArg(args, "new_string")
		if err != nil {
			return "", "", "", 0, err
		}
		all, err := boolArg(args, "replace_all")
		if err != nil {
			return "", "", "", 0, err
		}
		abs, err = resolveWithin(root, path)
		if err != nil {
			return "", "", "", 0, err
		}
		src, err := readExisting(abs)
		if err != nil {
			return "", "", "", 0, err
		}
		updated, replacements, err = applyEdit(src, oldString, newString, all)
		if err != nil {
			return "", "", "", 0, fmt.Errorf("%s: %w", displayPath(root, abs), err)
		}
		return abs, displayPath(root, abs), updated, replacements, nil
	}

	return Tool{
		Name:        "edit_file",
		Description: "Replace an exact string in a file in the session workspace.",
		Parameters:  json.RawMessage(editFileSchema),
		Preview: func(args map[string]any) (*diff.FileDiff, error) {
			_, rel, updated, _, err := edit(args)
			if err != nil {
				return nil, err
			}
			path, _ := stringArg(args, "path")
			abs, _ := resolveWithin(root, path)
			old, _ := readExisting(abs)
			return diff.File(rel, old, updated), nil
		},
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			abs, rel, updated, replacements, err := edit(args)
			if err != nil {
				return "", err
			}
			//nolint:gosec // the path was resolved and confined to the workspace above.
			if err := os.WriteFile(abs, []byte(updated), 0o600); err != nil {
				return "", fmt.Errorf("write %s: %w", rel, err)
			}
			return fmt.Sprintf("edited %s (%d replacement(s))", rel, replacements), nil
		},
	}
}

// applyEdit replaces oldString in src. An empty oldString is refused (it would
// match everywhere); a non-unique oldString is refused unless all is set.
func applyEdit(src, oldString, newString string, all bool) (string, int, error) {
	if oldString == "" {
		return "", 0, errors.New("old_string must not be empty")
	}
	found := strings.Count(src, oldString)
	switch {
	case found == 0:
		return "", 0, errors.New("old_string was not found")
	case found > 1 && !all:
		return "", 0, fmt.Errorf("old_string occurs %d times; use replace_all or a more specific old_string", found)
	case all:
		return strings.ReplaceAll(src, oldString, newString), found, nil
	default:
		return strings.Replace(src, oldString, newString, 1), 1, nil
	}
}

// readExisting reads a file's contents, returning "" for a path that does not
// exist yet (a new file). A directory is an error.
func readExisting(abs string) (string, error) {
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory, not a file", abs)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", abs)
	}
	//nolint:gosec // the path was resolved and confined to the workspace by the caller.
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// lineCount renders a short line count for a write result.
func lineCount(s string) string {
	if s == "" {
		return "0 lines"
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	if n == 1 {
		return "1 line"
	}
	return fmt.Sprintf("%d lines", n)
}
