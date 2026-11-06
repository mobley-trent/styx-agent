package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/findingsexport"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
)

// TestHeadlessWritesFindingsExport covers docs/findings-export.md §5: --out on
// a non-interactive run writes all three artifacts, and a safe-mode run writes
// a valid empty export rather than nothing.
func TestHeadlessWritesFindingsExport(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "reports")
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("nothing found")))
	var out, errOut strings.Builder

	opts := headlessOptions(t, dir, fake, "look around", &out, &errOut)
	opts.OutDir = outDir
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read export directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	want := []string{findingsexport.CSVName, findingsexport.JSONName, findingsexport.SARIFName}
	for _, name := range want {
		if !contains(names, name) {
			t.Errorf("export directory holds %v, want %s", names, name)
		}
	}
	if len(names) != len(want) {
		t.Errorf("export directory holds %v, want exactly the three artifacts", names)
	}

	doc := readAppFile(t, filepath.Join(outDir, findingsexport.JSONName))
	for _, marker := range []string{`"engagement": null`, `"findings": []`, `"reported": 0`} {
		if !strings.Contains(doc, marker) {
			t.Errorf("empty export does not contain %q:\n%s", marker, doc)
		}
	}
	if !strings.Contains(errOut.String(), "styx: export 0 findings · 0 omitted") {
		t.Errorf("stderr does not report the export:\n%s", errOut.String())
	}
}

// TestHeadlessExportNamesTheEngagement covers §3.1: an engagement run names its
// engagement in the envelope, so a CI reader can tell two scans apart.
func TestHeadlessExportNamesTheEngagement(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "engagement.yaml", inSessionEngagement)
	outDir := filepath.Join(dir, "reports")
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("nothing found")))
	var out, errOut strings.Builder

	opts := headlessOptions(t, dir, fake, "look around", &out, &errOut)
	opts.Engagement = filepath.Join(dir, "engagement.yaml")
	opts.OutDir = outDir
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}

	doc := readAppFile(t, filepath.Join(outDir, findingsexport.JSONName))
	if !strings.Contains(doc, `"engagement": "in-session"`) {
		t.Errorf("export does not name the engagement:\n%s", doc)
	}
}

// TestHeadlessExportWriteFailureFailsTheRun covers §5: a pipeline that asked
// for an export never receives a half-written one, and the run fails rather
// than reporting success without it.
func TestHeadlessExportWriteFailureFailsTheRun(t *testing.T) {
	dir := t.TempDir()
	// A file where the directory should be makes the write impossible.
	writeFile(t, dir, "reports", "not a directory\n")
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("nothing found")))
	var out, errOut strings.Builder

	opts := headlessOptions(t, dir, fake, "look around", &out, &errOut)
	opts.OutDir = filepath.Join(dir, "reports")
	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run() = nil, want a failed export write")
	}
	if !strings.Contains(err.Error(), "findings export") {
		t.Errorf("error = %v, want it to name the export", err)
	}
	if !strings.Contains(errOut.String(), "! export failed:") {
		t.Errorf("stderr does not report the failed export:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "styx: done —") {
		t.Errorf("stderr has no end summary after a failed export:\n%s", errOut.String())
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
