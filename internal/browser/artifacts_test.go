package browser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeDownloadName(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "../../etc/passwd", want: "passwd"},
		{raw: "/etc/shadow", want: "shadow"},
		{raw: `..\..\windows\win.ini`, want: "win.ini"},
		{raw: "\x00evil.txt", want: "evil.txt"},
		{raw: "../\x01\x02payload.bin", want: "payload.bin"},
		{raw: ".bashrc", want: "file-bashrc"},
		{raw: "..", want: "download"},
		{raw: ".", want: "download"},
		{raw: "", want: "download"},
		{raw: "   ", want: "download"},
		{raw: "report final.pdf", want: "report final.pdf"},
		{raw: "a/b/../c.txt", want: "c.txt"},
		{raw: "%2e%2e%2fevil", want: "%2e%2e%2fevil"},
		{raw: strings.Repeat("a", 300) + ".zip", want: strings.Repeat("a", 100) + ".zip"},
	}
	for _, tt := range tests {
		if got := SanitizeDownloadName(tt.raw); got != tt.want {
			t.Errorf("SanitizeDownloadName(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestArtifactPathsAreConfinedToTheSessionDirectories(t *testing.T) {
	project := t.TempDir()
	shot := ScreenshotDir(project, "../../escape")
	download := DownloadDir(project, "../escape")
	for _, dir := range []string{shot, download} {
		if strings.Contains(filepath.ToSlash(dir), "../") {
			t.Errorf("artifact directory %q escapes the project", dir)
		}
		if !strings.HasPrefix(dir, project+string(filepath.Separator)) {
			t.Errorf("artifact directory %q is outside the project", dir)
		}
	}
}

func TestNextScreenshotPathCountsUp(t *testing.T) {
	dir := t.TempDir()
	first, err := NextScreenshotPath(dir)
	if err != nil {
		t.Fatalf("NextScreenshotPath() = %v", err)
	}
	if filepath.Base(first) != "shot-1.png" {
		t.Errorf("first = %q, want shot-1.png", first)
	}
	for _, name := range []string{"shot-1.png", "shot-2.png"} {
		//nolint:gosec // test fixture in a temporary directory.
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	next, err := NextScreenshotPath(dir)
	if err != nil {
		t.Fatalf("NextScreenshotPath() = %v", err)
	}
	if filepath.Base(next) != "shot-3.png" {
		t.Errorf("next = %q, want shot-3.png", next)
	}
}

func TestUniquePathAvoidsOverwriting(t *testing.T) {
	dir := t.TempDir()
	//nolint:gosec // test fixture in a temporary directory.
	if err := os.WriteFile(filepath.Join(dir, "report.pdf"), []byte("one"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := filepath.Base(UniquePath(dir, "report.pdf")); got != "report-2.pdf" {
		t.Errorf("UniquePath() = %q, want report-2.pdf", got)
	}
}

func TestWriteArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shot-1.png")
	n, err := WriteArtifact(path, []byte("png-bytes"))
	if err != nil {
		t.Fatalf("WriteArtifact() = %v", err)
	}
	if n != int64(len("png-bytes")) {
		t.Errorf("WriteArtifact() = %d bytes, want %d", n, len("png-bytes"))
	}
	data, err := os.ReadFile(path) //nolint:gosec // a test-only read of a path the test itself built.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "png-bytes" {
		t.Errorf("artifact = %q", data)
	}
}
