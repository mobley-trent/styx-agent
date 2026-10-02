package agent

import (
	"context"
	"strings"
	"testing"
)

func TestGlobToolMatches(t *testing.T) {
	dir := workspace(t, map[string]string{
		"main.go":            "package main\n",
		"internal/a.go":      "package a\n",
		"internal/a_test.go": "package a\n",
		"docs/readme.md":     "hi\n",
		".git/config":        "ignored\n",
	})
	tool := GlobTool(dir)

	tests := []struct {
		name    string
		args    map[string]any
		want    []string
		absent  []string
		wantErr bool
	}{
		{name: "extension", args: map[string]any{"pattern": "*.go"}, want: []string{"internal/a.go", "internal/a_test.go", "main.go"}},
		{name: "base name", args: map[string]any{"pattern": "readme.md"}, want: []string{"docs/readme.md"}},
		{name: "nested", args: map[string]any{"pattern": "internal/*.go"}, want: []string{"internal/a.go", "internal/a_test.go"}, absent: []string{"main.go"}},
		{name: "double star", args: map[string]any{"pattern": "**/*_test.go"}, want: []string{"internal/a_test.go"}},
		{name: "no match", args: map[string]any{"pattern": "*.rs"}, want: []string{"no files match"}},
		{name: "empty", args: map[string]any{"pattern": ""}, wantErr: true},
		{name: "missing", args: map[string]any{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tool.Handler(context.Background(), tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Handler() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Handler() = %v", err)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("Handler() = %q, want it to contain %q", got, want)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(got, absent) {
					t.Errorf("Handler() = %q, want it not to contain %q", got, absent)
				}
			}
			if strings.Contains(got, ".git") {
				t.Errorf("Handler() = %q, want .git skipped", got)
			}
		})
	}
}

func TestGlobToolLimit(t *testing.T) {
	files := map[string]string{}
	for _, name := range []string{"a.go", "b.go", "c.go", "d.go"} {
		files[name] = "package x\n"
	}
	dir := workspace(t, files)
	got, err := GlobTool(dir).Handler(context.Background(), map[string]any{"pattern": "*.go", "limit": 2})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, ".go") != 2 || !strings.Contains(got, "first 2 matches") {
		t.Errorf("Handler(limit=2) = %q, want exactly two matches and a truncation marker", got)
	}
}

func TestGrepToolFindsLines(t *testing.T) {
	dir := workspace(t, map[string]string{
		"main.go":       "package main\n\nfunc main() {}\n",
		"other.txt":     "main street\n",
		"internal/a.go": "package a\nvar x = 1\n",
	})
	tool := GrepTool(dir)

	got, err := tool.Handler(context.Background(), map[string]any{"pattern": "func main"})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if !strings.Contains(got, "main.go:3: func main() {}") {
		t.Errorf("Handler() = %q, want the matching line with its number", got)
	}

	got, err = tool.Handler(context.Background(), map[string]any{"pattern": "main", "glob": "*.go"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "other.txt") {
		t.Errorf("glob filter was ignored: %q", got)
	}

	got, err = tool.Handler(context.Background(), map[string]any{"pattern": "zzz"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "no matches") {
		t.Errorf("Handler(no match) = %q, want a no-match message", got)
	}
}

func TestGrepToolErrors(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "hello\n"})
	tool := GrepTool(dir)

	if _, err := tool.Handler(context.Background(), map[string]any{"pattern": "("}); err == nil {
		t.Error("Handler(invalid regex) = nil error, want a compile error")
	}
	if _, err := tool.Handler(context.Background(), map[string]any{"pattern": "x", "path": "../outside"}); err == nil {
		t.Error("Handler(escaping path) = nil error, want a confinement error")
	}
	if _, err := tool.Handler(context.Background(), map[string]any{"pattern": "x", "path": "does-not-exist"}); err == nil {
		t.Error("Handler(missing path) = nil error, want an error")
	}
}

func TestGrepToolLimit(t *testing.T) {
	dir := workspace(t, map[string]string{"many.txt": "hit\nhit\nhit\nhit\n"})
	got, err := GrepTool(dir).Handler(context.Background(), map[string]any{"pattern": "hit", "limit": 2})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "hit") != 2 || !strings.Contains(got, "limit") {
		t.Errorf("Handler(limit=2) = %q, want two matches and a truncation marker", got)
	}
}
