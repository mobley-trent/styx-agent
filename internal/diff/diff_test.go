package diff

import (
	"fmt"
	"strings"
	"testing"
)

func TestFileIdentical(t *testing.T) {
	d := File("main.go", "a\nb\nc\n", "a\nb\nc\n")
	if !d.Empty() {
		t.Fatalf("Empty() = false, want true: %+v", d)
	}
	if got := d.Unified(); got != "" {
		t.Errorf("Unified() = %q, want empty", got)
	}
}

func TestFileLineNumbers(t *testing.T) {
	d := File("main.go", "one\ntwo\nthree\n", "one\nTWO\nthree\n")
	if d.Empty() {
		t.Fatal("Empty() = true, want a change")
	}
	if d.Added != 1 || d.Removed != 1 {
		t.Errorf("Added/Removed = %d/%d, want 1/1", d.Added, d.Removed)
	}
	want := []Line{
		{Op: OpContext, Text: "one", Old: 1, New: 1},
		{Op: OpRemove, Text: "two", Old: 2},
		{Op: OpAdd, Text: "TWO", New: 2},
		{Op: OpContext, Text: "three", Old: 3, New: 3},
	}
	if fmt.Sprintf("%+v", d.Lines) != fmt.Sprintf("%+v", want) {
		t.Errorf("Lines = %+v, want %+v", d.Lines, want)
	}
}

func TestFileInsertAndDelete(t *testing.T) {
	ins := File("f.txt", "a\nb\n", "a\nx\nb\n")
	if ins.Added != 1 || ins.Removed != 0 {
		t.Errorf("insert Added/Removed = %d/%d, want 1/0", ins.Added, ins.Removed)
	}
	del := File("f.txt", "a\nx\nb\n", "a\nb\n")
	if del.Added != 0 || del.Removed != 1 {
		t.Errorf("delete Added/Removed = %d/%d, want 0/1", del.Added, del.Removed)
	}
}

func TestFileNewAndEmpty(t *testing.T) {
	d := File("new.go", "", "package main\n")
	if d.Removed != 0 || d.Added != 1 {
		t.Errorf("new file Added/Removed = %d/%d, want 1/0", d.Added, d.Removed)
	}
	if !strings.Contains(d.Unified(), "@@ -0,0 +1 @@") {
		t.Errorf("new-file hunk header missing:\n%s", d.Unified())
	}

	gone := File("gone.go", "package main\n", "")
	if gone.Added != 0 || gone.Removed != 1 {
		t.Errorf("deleted file Added/Removed = %d/%d, want 0/1", gone.Added, gone.Removed)
	}
}

func TestUnifiedRendering(t *testing.T) {
	d := File("pkg/f.go", "a\nb\nc\nd\ne\nf\ng\nh\n", "a\nb\nc\nd\nE\nf\ng\nh\n")
	got := d.Unified()
	for _, want := range []string{"--- a/pkg/f.go", "+++ b/pkg/f.go", "@@ -2,7 +2,7 @@", " d", "-e", "+E", " h"} {
		if !strings.Contains(got, want) {
			t.Errorf("Unified() missing %q:\n%s", want, got)
		}
	}
}

func TestHunksSplitOnDistantChanges(t *testing.T) {
	var before, after strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&before, "line %d\n", i)
		fmt.Fprintf(&after, "line %d\n", i)
	}
	// Two changes far enough apart to be separate hunks.
	oldLines := strings.Split(strings.TrimRight(before.String(), "\n"), "\n")
	newLines := strings.Split(strings.TrimRight(after.String(), "\n"), "\n")
	newLines[1] = "changed one"
	newLines[38] = "changed two"
	joined := func(ls []string) string { return strings.Join(ls, "\n") + "\n" }

	d := File("big.txt", joined(oldLines), joined(newLines))
	if got := strings.Count(d.Unified(), "@@"); got/2 != 2 {
		t.Errorf("hunk count = %d, want 2:\n%s", got/2, d.Unified())
	}
}

func TestLargeFilesFallBack(t *testing.T) {
	a := make([]string, maxLCSLines+1)
	b := make([]string, maxLCSLines+1)
	for i := range a {
		a[i] = "a"
		b[i] = "a"
	}
	b[len(b)-1] = "b"
	d := File("huge.txt", strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n")
	if d.Empty() {
		t.Fatal("fallback diff reports no change")
	}
	// The fallback removes the whole old file and adds the whole new one.
	if d.Removed != len(a) || d.Added != len(b) {
		t.Errorf("fallback counts = +%d -%d, want +%d -%d", d.Added, d.Removed, len(b), len(a))
	}
}

func TestSummary(t *testing.T) {
	d := File("x.go", "a\n", "a\nb\n")
	if got := d.Summary(); got != "x.go (+1 -0)" {
		t.Errorf("Summary() = %q, want %q", got, "x.go (+1 -0)")
	}
}
