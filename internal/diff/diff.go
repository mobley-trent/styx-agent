package diff

import (
	"fmt"
	"strings"
)

// Op is one line's role in a diff.
type Op string

const (
	// OpContext is an unchanged line.
	OpContext Op = " "
	// OpAdd is a line present only in the new version.
	OpAdd Op = "+"
	// OpRemove is a line present only in the old version.
	OpRemove Op = "-"
)

// Line is one diff line. Old and New are 1-based line numbers in the old and
// new files respectively; the number that does not apply is zero (an added
// line has no old number).
type Line struct {
	Op   Op     `json:"op"`
	Text string `json:"text"`
	Old  int    `json:"old,omitempty"`
	New  int    `json:"new,omitempty"`
}

// FileDiff is the line diff between two versions of one file.
type FileDiff struct {
	// Path is the file's path as the operator and model know it.
	Path string `json:"path"`
	// Lines is the diff, in file order.
	Lines []Line `json:"lines"`
	// Added and Removed count changed lines.
	Added   int `json:"added"`
	Removed int `json:"removed"`
}

// maxLCSLines bounds the quadratic LCS table. Beyond it the diff degrades to a
// whole-file replacement rather than allocating an unbounded amount of memory.
const maxLCSLines = 1500

// ContextLines is how many unchanged lines a unified hunk keeps around a
// change.
const ContextLines = 3

// File computes the diff from oldText to newText for the file at path.
func File(path, oldText, newText string) *FileDiff {
	lines := diffLines(splitLines(oldText), splitLines(newText))
	d := &FileDiff{Path: path, Lines: lines}
	for _, ln := range lines {
		switch ln.Op {
		case OpAdd:
			d.Added++
		case OpRemove:
			d.Removed++
		}
	}
	return d
}

// Empty reports whether the two versions are identical.
func (d *FileDiff) Empty() bool { return d.Added == 0 && d.Removed == 0 }

// Summary is a one-line "path (+added -removed)" description.
func (d *FileDiff) Summary() string {
	return fmt.Sprintf("%s (+%d -%d)", d.Path, d.Added, d.Removed)
}

// hunk is one unified-diff hunk: a maximal run of changes plus ContextLines of
// surrounding unchanged lines.
type hunk struct {
	oldRange string
	newRange string
	lines    []Line
}

// hunks groups the diff's lines into unified hunks.
func (d *FileDiff) hunks() []hunk {
	var out []hunk
	i, n := 0, len(d.Lines)
	for i < n {
		if d.Lines[i].Op == OpContext {
			i++
			continue
		}
		start := i - ContextLines
		if start < 0 {
			start = 0
		}
		// Extend to the last change, then include ContextLines unchanged
		// lines past it. Changes within the window join the same hunk.
		end, lastChange := i, i
		for end < n {
			if d.Lines[end].Op != OpContext {
				lastChange = end
				end++
				continue
			}
			end++
			if end-lastChange-1 >= ContextLines {
				break
			}
		}
		lines := d.Lines[start:end]
		out = append(out, hunk{
			oldRange: rangeText(lines, true),
			newRange: rangeText(lines, false),
			lines:    lines,
		})
		i = end
	}
	return out
}

// rangeText renders a hunk header's line range for one side.
func rangeText(lines []Line, old bool) string {
	start, count := 0, 0
	for _, ln := range lines {
		no := ln.New
		if old {
			no = ln.Old
		}
		if no == 0 {
			continue
		}
		if start == 0 {
			start = no
		}
		count++
	}
	switch count {
	case 0:
		if old {
			return "0,0"
		}
		return fmt.Sprintf("%d,0", start)
	case 1:
		return fmt.Sprintf("%d", start)
	default:
		return fmt.Sprintf("%d,%d", start, count)
	}
}

// Unified renders the diff in unified form with hunk headers and context.
func (d *FileDiff) Unified() string {
	if d.Empty() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", d.Path, d.Path)
	for _, h := range d.hunks() {
		fmt.Fprintf(&b, "@@ -%s +%s @@\n", h.oldRange, h.newRange)
		for _, ln := range h.lines {
			b.WriteString(string(ln.Op))
			b.WriteString(ln.Text)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// splitLines splits text into lines, without a trailing empty element for a
// final newline. An empty document has no lines.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// diffLines computes an LCS-based diff of two line slices.
func diffLines(a, b []string) []Line {
	if len(a) > maxLCSLines || len(b) > maxLCSLines {
		return replaceAll(a, b)
	}
	n, m := len(a), len(b)

	// dp[i][j] is the LCS length of a[i:] and b[j:], filled from the end so
	// the walk below can consume it greedily.
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				dp[i][j] = dp[i+1][j+1] + 1
			case dp[i+1][j] >= dp[i][j+1]:
				dp[i][j] = dp[i+1][j]
			default:
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	out := make([]Line, 0, n+m)
	i, j := 0, 0
	oldNo, newNo := 1, 1
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, Line{Op: OpContext, Text: a[i], Old: oldNo, New: newNo})
			i++
			j++
			oldNo++
			newNo++
		case dp[i+1][j] >= dp[i][j+1]:
			out = append(out, Line{Op: OpRemove, Text: a[i], Old: oldNo})
			i++
			oldNo++
		default:
			out = append(out, Line{Op: OpAdd, Text: b[j], New: newNo})
			j++
			newNo++
		}
	}
	for ; i < n; i++ {
		out = append(out, Line{Op: OpRemove, Text: a[i], Old: oldNo})
		oldNo++
	}
	for ; j < m; j++ {
		out = append(out, Line{Op: OpAdd, Text: b[j], New: newNo})
		newNo++
	}
	return out
}

// replaceAll is the bounded fallback for files too large to diff: the old
// version wholesale removed, the new wholesale added.
func replaceAll(a, b []string) []Line {
	out := make([]Line, 0, len(a)+len(b))
	for i, s := range a {
		out = append(out, Line{Op: OpRemove, Text: s, Old: i + 1})
	}
	for i, s := range b {
		out = append(out, Line{Op: OpAdd, Text: s, New: i + 1})
	}
	return out
}
