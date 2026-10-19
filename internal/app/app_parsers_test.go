package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// artifactExec is a session-container stand-in that writes the artifact its
// command names, so the artifact watch sees what a real scanner run would
// leave behind. Everything else it is asked to run succeeds with no output.
type artifactExec struct {
	workspace string
	source    string
}

func (e artifactExec) Shell(_ context.Context, command string) (string, error) {
	if !strings.Contains(command, "nmap-scan.xml") {
		return "", nil
	}
	body, err := os.ReadFile(e.source)
	if err != nil {
		return "", err
	}
	path := filepath.Join(e.workspace, ".styx", "out", "nmap-scan.xml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	//nolint:gosec // the path is the test's own workspace.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return "Nmap done: 256 IP addresses (1 host up) scanned", nil
}

func (e artifactExec) Code(context.Context, string, string) (string, error) { return "", nil }

// TestUnparsedArtifactReachesTheDigestUntilAParserReadsIt walks the whole §4
// obligation: a scan leaves an artifact, the harness notices without being
// told, the next turn's digest and the status bar both carry the directive, and
// a parser call clears them because the findings reached engagement state.
func TestUnparsedArtifactReachesTheDigestUntilAParserReadsIt(t *testing.T) {
	dir := t.TempDir()
	// A repository, so the artifact directory has a .gitignore to be added to.
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	source, err := filepath.Abs(filepath.Join("..", "testdata", "parsers", "nmap-scan.xml"))
	if err != nil {
		t.Fatal(err)
	}

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "bash", `{"command":"nmap -sV -oX .styx/out/nmap-scan.xml 10.0.0.5"}`)),
		fakemodel.Text("scan finished"),
		fakemodel.ToolCalls(fakemodel.Call("c2", "nmap_parse", `{"path":".styx/out/nmap-scan.xml"}`)),
		fakemodel.Text("parsed the scan"),
	))
	opts := buildOptions(t, dir, fake)
	opts.Engagement = engagementFixture
	opts.Executor = artifactExec{workspace: dir, source: source}

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// bash prompts; the operator in this test allows it once.
	h.setPromptUI(func(msg tui.PromptMsg) {
		if msg.Prompt.Kind == tui.PromptPermission {
			msg.Reply(tui.ChoiceAllowOnce)
		}
	})

	// Activation prepares the artifact convention: the directory exists, and
	// the repository ignores it.
	if info, err := os.Stat(filepath.Join(dir, ".styx", "out")); err != nil || !info.IsDir() {
		t.Fatalf("artifact directory not prepared: %v", err)
	}
	//nolint:gosec // the path is the test's own project.
	ignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore = %v", err)
	}
	if !strings.Contains(string(ignore), ".styx/") {
		t.Errorf(".gitignore = %q, want the artifact directory ignored", ignore)
	}
	if got := h.Status(false).Pending; got != "" {
		t.Errorf("status pending = %q before any scan, want empty", got)
	}

	// The scan runs; nothing tells the harness to expect an artifact.
	if err := h.Submit(context.Background(), "scan the target"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if got := h.Status(false).Pending; got != "parse 1 pending" {
		t.Fatalf("status pending = %q after the scan, want one obligation", got)
	}

	// The next turn's prompt carries the directive.
	if err := h.Submit(context.Background(), "what did we find"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	var directive bool
	for _, m := range h.Messages() {
		if strings.Contains(m.Content, "pending parse: .styx/out/nmap-scan.xml → nmap_parse") {
			directive = true
		}
	}
	if !directive {
		t.Errorf("no digest carried the pending-parse directive: %+v", h.Messages())
	}

	// Parsing it clears the obligation and lands the scan in state.
	if got := h.Status(false).Pending; got != "" {
		t.Errorf("status pending = %q after the parse, want empty", got)
	}
	snapshot := h.state.Snapshot()
	var host bool
	for _, e := range snapshot.Entities {
		if e.Kind == "host" {
			for _, addr := range e.Addresses {
				if addr == "10.0.0.5" {
					host = true
				}
			}
		}
	}
	if !host {
		t.Errorf("state has no host 10.0.0.5 after the parse: %+v", snapshot.Entities)
	}
	var services int
	for _, e := range snapshot.Entities {
		if e.Kind == "service" {
			services++
		}
	}
	if services != 3 {
		t.Errorf("state has %d services after the parse, want 3 open ones", services)
	}
	// A port is a fact, not a vulnerability: the nmap parser records services
	// and must not invent findings from them.
	if len(snapshot.Findings) != 0 {
		t.Errorf("nmap produced findings, want facts only: %+v", snapshot.Findings)
	}
}

// TestSafeModePreparesNoArtifactDirectory keeps the workspace contract honest:
// a safe session has no engagement and therefore no artifact convention to
// impose on the project.
func TestSafeModePreparesNoArtifactDirectory(t *testing.T) {
	dir := t.TempDir()
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("hello")))
	opts := buildOptions(t, dir, fake)

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if _, err := os.Stat(filepath.Join(dir, ".styx")); !os.IsNotExist(err) {
		t.Errorf("safe mode created an artifact directory: %v", err)
	}
	if got := h.Status(false).Pending; got != "" {
		t.Errorf("status pending = %q in safe mode, want empty", got)
	}
}
