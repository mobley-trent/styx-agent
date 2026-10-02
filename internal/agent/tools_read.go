package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxReadBytes bounds how much of a file read_file pulls into memory. The
// loop's capture truncation (§4.5) is a separate, smaller bound applied to
// every tool result; this one keeps a single read from ballooning the
// harness's own heap.
const maxReadBytes = 4 << 20 // 4 MiB

// readFileSchema is the read_file descriptor's JSON Schema (strict mode:
// every property is declared and additionalProperties is false).
const readFileSchema = `{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Path to the file to read, absolute or relative to the workspace root."
    }
  },
  "required": ["path"],
  "additionalProperties": false
}`

// ReadFileTool is the §5.1 read_file tool. It reads a file from the session
// workspace and returns its contents; every path is confined to the
// workspace root, so the tool cannot read outside it.
func ReadFileTool(workspace string) Tool {
	root, err := filepath.Abs(workspace)
	if err != nil {
		root = workspace
	}
	return Tool{
		Name:        "read_file",
		Description: "Read a file from the session workspace and return its contents.",
		Parameters:  json.RawMessage(readFileSchema),
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			path, err := stringArg(args, "path")
			if err != nil {
				return "", err
			}
			abs, err := resolveWithin(root, path)
			if err != nil {
				return "", err
			}
			return readConfined(abs)
		},
	}
}

// resolveWithin resolves a caller-supplied path against the workspace root and
// rejects anything that escapes it.
func resolveWithin(root, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is required")
	}
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, path)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the workspace", path)
	}
	return abs, nil
}

// readConfined reads a file, refusing anything that is not a regular file and
// capping the read at maxReadBytes.
func readConfined(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory, not a file", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}

	//nolint:gosec // the path was resolved and confined to the workspace above.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxReadBytes {
		return string(data[:maxReadBytes]) +
			fmt.Sprintf("\n[read_file: file is larger than %d bytes; only the first %d bytes were read]", maxReadBytes, maxReadBytes), nil
	}
	return string(data), nil
}
