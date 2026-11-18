package browser

import (
	"errors"
	"strings"
	"testing"
)

// sampleSnapshot is a page with structure around three interactive nodes.
func sampleSnapshot() rawSnapshot {
	return rawSnapshot{
		URL:   "http://10.0.0.5/login",
		Title: "Sign in",
		Nodes: []rawNode{
			{Parent: -1, Role: "heading", Name: "Welcome", Level: 1},
			{Parent: -1, Role: "link", Name: "Home", Interactive: true, Index: 0},
			{Parent: 1, Role: "paragraph", Name: "nested note"},
			{Parent: -1, Role: "textbox", Name: "Email", Interactive: true, Index: 1},
			{Parent: -1, Role: "button", Name: "Sign In", Interactive: true, Index: 2, Disabled: true},
		},
	}
}

func TestSnapshotRendersTreeWithPerSnapshotHandles(t *testing.T) {
	snap := newSnapshot(sampleSnapshot())
	text := snap.render(0)

	for _, want := range []string{
		"URL: http://10.0.0.5/login",
		"Title: Sign in",
		`- heading "Welcome" [level=1]`,
		`[1] link "Home"`,
		`  - paragraph "nested note"`,
		`[2] textbox "Email"`,
		`[3] button "Sign In" [disabled]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("render() = %q, want it to contain %q", text, want)
		}
	}
	if got := snap.Handles["1"]; got.Index != 1 || got.Role != "link" {
		t.Errorf("handle 1 = %+v, want the link node", got)
	}
	if len(snap.Handles) != 3 {
		t.Errorf("handles = %d, want one per interactive node", len(snap.Handles))
	}
}

func TestSnapshotReadsOneElement(t *testing.T) {
	snap := newSnapshot(sampleSnapshot())
	handle, err := snap.lookup("1")
	if err != nil {
		t.Fatalf("lookup(1) = %v", err)
	}
	text := snap.renderSubtree(handle, 0)
	want := "[1] link \"Home\"\n  - paragraph \"nested note\"\n"
	if text != want {
		t.Errorf("renderSubtree() = %q, want %q", text, want)
	}
}

func TestSnapshotRefusesAnUnknownHandle(t *testing.T) {
	snap := newSnapshot(sampleSnapshot())
	_, err := snap.lookup("9")
	if !errors.Is(err, ErrStaleHandle) {
		t.Fatalf("lookup(9) = %v, want ErrStaleHandle", err)
	}
	if !strings.Contains(err.Error(), "take a fresh snapshot") {
		t.Errorf("error = %v, want it to tell the model to take a fresh snapshot", err)
	}
	_, err = snap.lookup("  ")
	if !errors.Is(err, ErrStaleHandle) {
		t.Errorf("lookup(empty) = %v, want ErrStaleHandle", err)
	}
}

func TestSnapshotTruncatesExplicitly(t *testing.T) {
	snap := newSnapshot(rawSnapshot{
		URL:   "http://example.test/",
		Title: "Long",
		Nodes: []rawNode{{Parent: -1, Role: "paragraph", Name: strings.Repeat("word ", 100)}},
	})
	text := snap.render(40)
	if len(text) > 40+len("\n[browser_read: truncated at 40 characters]") {
		t.Errorf("render(40) returned %d characters, want the bound plus the truncation line", len(text))
	}
	if !strings.Contains(text, "[browser_read: truncated at 40 characters]") {
		t.Errorf("render(40) = %q, want an explicit truncation line", text)
	}
}

func TestTruncateCapsMaxChars(t *testing.T) {
	text := truncate(strings.Repeat("x", MaxChars*2), MaxChars*4)
	if !strings.Contains(text, "truncated at 32768 characters") {
		t.Errorf("truncate() did not cap at MaxChars: %q", text[len(text)-80:])
	}
}

func TestSnapshotOnlyNumbersWhatItRenders(t *testing.T) {
	nodes := make([]rawNode, 0, 20)
	for i := 0; i < 20; i++ {
		parent := -1
		if i > 0 {
			parent = i - 1
		}
		nodes = append(nodes, rawNode{Parent: parent, Role: "link", Name: "deep", Interactive: true, Index: i})
	}
	snap := newSnapshot(rawSnapshot{URL: "http://example.test/", Nodes: nodes})
	if got := len(snap.Handles); got != maxIndentDepth+1 {
		t.Errorf("handles = %d, want %d: a handle must address what the snapshot showed", got, maxIndentDepth+1)
	}
}

func TestCleanNameCollapsesWhitespace(t *testing.T) {
	if got := cleanName("Hello\n\t  world  !"); got != "Hello world !" {
		t.Errorf("cleanName() = %q, want the whitespace collapsed", got)
	}
	if got := cleanName(strings.Repeat("x", maxNameRunes+50)); len([]rune(got)) > maxNameRunes+1 {
		t.Errorf("cleanName() = %d runes, want the bound", len([]rune(got)))
	}
}

func TestSnapshotSaysWhenNothingIsAccessible(t *testing.T) {
	text := newSnapshot(rawSnapshot{URL: "http://example.test/"}).render(0)
	if !strings.Contains(text, "(no accessible nodes)") {
		t.Errorf("render() = %q, want an explicit empty-page line", text)
	}
}
