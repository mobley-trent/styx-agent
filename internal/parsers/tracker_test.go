package parsers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedClock is the tracker-clock stub.
func fixedClock(at time.Time) func() time.Time { return func() time.Time { return at } }

// writeArtifact puts content in a workspace's designated artifact directory.
func writeArtifact(t *testing.T, workspace, name, content string) string {
	t.Helper()
	dir := filepath.Join(workspace, ArtifactDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestNoteCommandAttributesAScannerRun(t *testing.T) {
	cases := []struct {
		command string
		parser  string
	}{
		{"nmap -sV -oX .styx/out/scan.xml 10.0.0.0/24", NmapParse},
		{"sudo nmap -sV 10.0.0.5", NmapParse},
		{"/usr/bin/nmap -p- 10.0.0.5", NmapParse},
		{"nuclei -u http://10.0.0.5 -jsonl -o .styx/out/nuclei.jsonl", NucleiParse},
		{"python3 sqlmap.py -u http://10.0.0.5/x?id=1 --dbs", SQLMapParse},
		{"gobuster dir -u http://10.0.0.5 -w wl.txt", GobusterParse},
		{"nxc smb 10.0.0.5 -u admin -p hunter2", CMEParse},
		{"crackmapexec smb 10.0.0.5 -u admin -p hunter2", CMEParse},
		{"bloodhound-python -c All -d acme.local", BloodHoundParse},
		{"man nmap", ""},
		{"which sqlmap", ""},
		{"apt-get install -y nmap nuclei", ""},
		{"echo 'nuclei is installed'", ""},
		{"go build ./...", ""},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			tracker := NewTracker(t.TempDir()).WithClock(fixedClock(time.Unix(0, 0).UTC()))
			tracker.NoteCommand(tc.command)
			if tc.parser == "" {
				if tracker.Count() != 0 {
					t.Errorf("Count() = %d, want no obligation for %q", tracker.Count(), tc.command)
				}
				return
			}
			if tracker.Count() != 1 {
				t.Fatalf("Count() = %d, want one run obligation", tracker.Count())
			}
			lines := strings.Join(tracker.Lines(), "\n")
			if !strings.Contains(lines, tc.parser) {
				t.Errorf("Lines() = %q, want the expected parser %s", lines, tc.parser)
			}
			if !tracker.Due() {
				t.Error("Due() = false, want a detection to be digest-worthy")
			}
		})
	}
}

func TestReconcileWatchesTheArtifactDirectory(t *testing.T) {
	workspace := t.TempDir()
	writeArtifact(t, workspace, "nmap-10.0.0.0_24.xml", "<nmaprun></nmaprun>")
	writeArtifact(t, workspace, "cme-10.0.0.5.log", "SMB 10.0.0.5 445 DC01 [+] LSA Secrets\n")
	writeArtifact(t, workspace, "notes.txt", "nothing a parser recognizes\n")

	tracker := NewTracker(workspace)
	tracker.Reconcile()

	pending := tracker.Pending()
	if len(pending) != 3 {
		t.Fatalf("Pending() = %d obligations, want 3", len(pending))
	}
	byArtifact := map[string]Obligation{}
	for _, obligation := range pending {
		byArtifact[obligation.Artifact] = obligation
	}
	xml, ok := byArtifact[ArtifactDir+"/nmap-10.0.0.0_24.xml"]
	if !ok || xml.Parser != NmapParse || xml.Scanner != "nmap" {
		t.Errorf("xml obligation = %+v, want the nmap parser", xml)
	}
	log, ok := byArtifact[ArtifactDir+"/cme-10.0.0.5.log"]
	if !ok || log.Parser != CMEParse {
		t.Errorf("log obligation = %+v, want the cme parser", log)
	}
	unknown, ok := byArtifact[ArtifactDir+"/notes.txt"]
	if !ok || unknown.Parser != "" {
		t.Errorf("unknown obligation = %+v, want a generic nudge", unknown)
	}

	lines := tracker.Lines()
	if !strings.Contains(strings.Join(lines, "\n"), "pending parse: "+ArtifactDir+"/nmap-10.0.0.0_24.xml → "+NmapParse) {
		t.Errorf("Lines() = %v, want the contract's `pending parse: <artifact> → <parser>` shape", lines)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "no parser recognizes it yet") {
		t.Errorf("Lines() = %v, want the generic nudge for the unrecognized artifact", lines)
	}
	if !strings.Contains(lines[len(lines)-1], "only through a parser") {
		t.Errorf("Lines() = %v, want the directive (§4)", lines)
	}
	if tracker.Count() != 3 {
		t.Errorf("Count() = %d, want the status bar's 3", tracker.Count())
	}
}

func TestReconcileIsIdempotentAndClearsWhatIsGone(t *testing.T) {
	workspace := t.TempDir()
	path := writeArtifact(t, workspace, "nmap.xml", "<nmaprun></nmaprun>")
	tracker := NewTracker(workspace)

	tracker.Reconcile()
	first := tracker.Count()
	tracker.Surfaced()
	tracker.Reconcile()
	if tracker.Count() != first {
		t.Errorf("Count() = %d after a second reconcile, want %d", tracker.Count(), first)
	}
	if tracker.Due() {
		t.Error("an unchanged obligation set is not digest-worthy")
	}

	// The artifact's removal is the operator's waiver (§4).
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	tracker.Reconcile()
	if tracker.Count() != 0 {
		t.Errorf("Count() = %d, want the removed artifact's obligation cleared", tracker.Count())
	}
	if len(tracker.Lines()) != 0 {
		t.Errorf("Lines() = %v, want nothing pending", tracker.Lines())
	}
	if !tracker.Due() {
		t.Error("clearing an obligation is digest-worthy")
	}
}

func TestClearSettlesTheArtifactAndItsRun(t *testing.T) {
	workspace := t.TempDir()
	path := writeArtifact(t, workspace, "nmap.xml", "<nmaprun></nmaprun>")
	tracker := NewTracker(workspace)
	tracker.NoteCommand("nmap -sV -oX .styx/out/nmap.xml 10.0.0.5")
	tracker.Reconcile()
	if tracker.Count() != 2 {
		t.Fatalf("Count() = %d, want the artifact and the run", tracker.Count())
	}

	tracker.Clear(path)
	if tracker.Count() != 0 {
		t.Errorf("Count() = %d, want a successful parse to clear both (§4)", tracker.Count())
	}
	if got := tracker.Pending(); len(got) != 0 {
		t.Errorf("Pending() = %+v, want none", got)
	}
}

func TestParsedArtifactIsNotNudgedAgainUntilItChanges(t *testing.T) {
	workspace := t.TempDir()
	path := writeArtifact(t, workspace, "nmap.xml", "<nmaprun></nmaprun>")
	tracker := NewTracker(workspace)
	tracker.Reconcile()
	tracker.Clear(path)
	tracker.Surfaced()

	// Parsed artifacts stay on disk — they are evidence — so reconciling must
	// not re-open the obligation for the version the parser already read.
	tracker.Reconcile()
	if tracker.Count() != 0 {
		t.Fatalf("Count() = %d after reconciling a parsed artifact, want none", tracker.Count())
	}
	if tracker.Due() {
		t.Error("a re-read of the same artifact is not digest-worthy")
	}

	// A rewrite is a new artifact: the scanner ran again, and this output is
	// unread.
	writeArtifact(t, workspace, "nmap.xml", "<nmaprun><host/></nmaprun>")
	tracker.Reconcile()
	if tracker.Count() != 1 {
		t.Fatalf("Count() = %d after the artifact was rewritten, want one obligation", tracker.Count())
	}
	if !tracker.Due() {
		t.Error("a rewritten artifact is digest-worthy")
	}

	// Removing it waives the obligation, and a later reuse of the path is a
	// new artifact rather than a re-read of the parsed one.
	tracker.Clear(path)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	tracker.Reconcile()
	writeArtifact(t, workspace, "nmap.xml", "<nmaprun></nmaprun>")
	tracker.Reconcile()
	if tracker.Count() != 1 {
		t.Errorf("Count() = %d after the path was reused, want a new obligation", tracker.Count())
	}
}

func TestSurfacedMakesRunDirectivesOneTurn(t *testing.T) {
	tracker := NewTracker(t.TempDir())
	tracker.NoteCommand("nuclei -u http://10.0.0.5")
	if !strings.Contains(strings.Join(tracker.Lines(), "\n"), "run was detected") {
		t.Fatalf("Lines() = %v, want the run directive", tracker.Lines())
	}
	tracker.Surfaced()
	if lines := tracker.Lines(); len(lines) != 0 {
		t.Errorf("Lines() = %v, want the run directive to be one turn only", lines)
	}
	if tracker.Due() {
		t.Error("Due() = true after the set was surfaced")
	}
}

func TestPendingLinesAreCapped(t *testing.T) {
	workspace := t.TempDir()
	for _, name := range []string{"a.xml", "b.xml", "c.xml", "d.xml", "e.xml", "f.xml", "g.xml", "h.xml"} {
		writeArtifact(t, workspace, name, "<nmaprun></nmaprun>")
	}
	tracker := NewTracker(workspace)
	tracker.Reconcile()
	lines := tracker.Lines()
	if len(lines) != maxPendingLines+2 {
		t.Fatalf("Lines() = %d lines, want %d pending + elision + directive", len(lines), maxPendingLines)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "more pending parse") {
		t.Errorf("Lines() = %v, want an elision line", lines)
	}
}

func TestSniffArtifactNamesLikelyParsers(t *testing.T) {
	cases := []struct {
		name    string
		content string
		parser  string
		scanner string
	}{
		{"scan.xml", "<?xml version=\"1.0\"?>\n<nmaprun scanner=\"nmap\">", NmapParse, "nmap"},
		{"out.xml", "<?xml version=\"1.0\"?>\n<results>", "", ""},
		{"results.jsonl", `{"template-id":"x"}`, NucleiParse, "nuclei"},
		{"array.json", `[{"template-id":"x"}]`, NucleiParse, "nuclei"},
		{"computers.json", `{"computers":[{"Properties":{}}]}`, BloodHoundParse, "BloodHound"},
		{"scan.log", "[09:10:03] [INFO] GET parameter 'id' is 'MySQL' injectable", SQLMapParse, "sqlmap"},
		{"nxc.log", "SMB 10.0.0.5 445 DC01 [+] LSA Secrets", CMEParse, "CrackMapExec/NetExec"},
		{"dir.txt", "/admin (Status: 301) [Size: 178]", GobusterParse, "gobuster"},
		{"dns.txt", "Found: dev.acme.example", GobusterParse, "gobuster"},
		{"notes.md", "# engagement notes", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			parser, scanner := sniffArtifact(path)
			if parser != tc.parser || scanner != tc.scanner {
				t.Errorf("sniffArtifact(%s) = (%q, %q), want (%q, %q)", tc.name, parser, scanner, tc.parser, tc.scanner)
			}
		})
	}
}

func TestPrepareWorkspaceCreatesTheDirectoryAndTheIgnoreEntry(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, ".gitignore"), []byte("node_modules/\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := PrepareWorkspace(workspace); err != nil {
		t.Fatalf("PrepareWorkspace() = %v", err)
	}
	info, err := os.Stat(filepath.Join(workspace, ArtifactDir))
	if err != nil || !info.IsDir() {
		t.Fatalf("artifact directory: %v", err)
	}
	content := readFile(t, filepath.Join(workspace, ".gitignore"))
	if !strings.Contains(content, "\n"+gitignoreEntry+"\n") {
		t.Errorf(".gitignore = %q, want the artifact entry appended", content)
	}
	if !strings.HasPrefix(content, "node_modules/\n") {
		t.Errorf(".gitignore = %q, want the project's own entry kept", content)
	}

	// Idempotent, and an equivalent entry in any spelling is left alone.
	if err := PrepareWorkspace(workspace); err != nil {
		t.Fatalf("PrepareWorkspace() twice = %v", err)
	}
	if again := readFile(t, filepath.Join(workspace, ".gitignore")); again != content {
		t.Errorf(".gitignore changed on a second call: %q", again)
	}

	for _, spelling := range []string{".styx/", "/.styx/", ".styx"} {
		other := t.TempDir()
		original := spelling + "\n"
		if err := os.WriteFile(filepath.Join(other, ".gitignore"), []byte(original), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := PrepareWorkspace(other); err != nil {
			t.Fatalf("PrepareWorkspace() = %v", err)
		}
		if got := readFile(t, filepath.Join(other, ".gitignore")); got != original {
			t.Errorf(".gitignore with %q = %q, want it untouched", spelling, got)
		}
	}
}

func TestPrepareWorkspaceSkipsAProjectWithNoRepository(t *testing.T) {
	workspace := t.TempDir()
	if err := PrepareWorkspace(workspace); err != nil {
		t.Fatalf("PrepareWorkspace() = %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace, ".gitignore")); !os.IsNotExist(err) {
		t.Error("a project with no .git and no .gitignore should not have one created for it")
	}
	if _, err := os.Stat(filepath.Join(workspace, ArtifactDir)); err != nil {
		t.Errorf("artifact directory: %v", err)
	}
}

func TestPrepareWorkspaceAddsAEntryToARepositoryWithoutAnIgnoreFile(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := PrepareWorkspace(workspace); err != nil {
		t.Fatalf("PrepareWorkspace() = %v", err)
	}
	content := readFile(t, filepath.Join(workspace, ".gitignore"))
	if !strings.Contains(content, gitignoreEntry) || !strings.Contains(content, gitignoreNote) {
		t.Errorf(".gitignore = %q, want the artifact entry", content)
	}
}

// readFile reads a test file that must exist.
func readFile(t *testing.T, path string) string {
	t.Helper()
	//nolint:gosec // tests read files they just wrote.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
