package parsers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ArtifactDir is the designated artifact directory under the project root
// (§3): the CLI writes raw scanner output there, the harness bind-mounts it as
// the session workspace, and the artifact watch can therefore see it appear
// even when argv sniffing misses a wrapped or scripted run.
const ArtifactDir = ".styx/out"

// gitignoreEntry is the line the harness additively writes into a project's
// .gitignore (§3): artifacts are evidence, and evidence does not belong in the
// repository.
const (
	gitignoreEntry = ".styx/"
	gitignoreNote  = "# styx: scanned artifacts and evidence (never committed)"
)

// maxPendingLines bounds the digest's pending-parse block, so a directory full
// of artifacts cannot crowd out the state digest itself.
const maxPendingLines = 6

// knownScanners maps a scanner to the parser that reads its output, in a stable
// order. The aliases are what argv sniffing looks for.
var knownScanners = []struct {
	// name is the scanner as a human names it.
	name string
	// parser is the parser tool that reads its output.
	parser string
	// argv are the command names the scanner is invoked as.
	argv []string
}{
	{"nmap", NmapParse, []string{"nmap"}},
	{"nuclei", NucleiParse, []string{"nuclei"}},
	{"sqlmap", SQLMapParse, []string{"sqlmap"}},
	{"gobuster", GobusterParse, []string{"gobuster"}},
	{"CrackMapExec/NetExec", CMEParse, []string{"cme", "nxc", "netexec", "crackmapexec"}},
	{"BloodHound", BloodHoundParse, []string{"bloodhound-python", "sharphound", "invoke-bloodhound"}},
}

// nonInvokingCommands are the command words that only name a tool, read about
// it, or install it, rather than run it: a command that starts with one is not a
// scanner run. §4's sniffing is best-effort by design, and this list is what
// keeps the obvious false positives ("man nmap", "apt-get install nmap") out of
// the directive.
var nonInvokingCommands = map[string]bool{
	"man": true, "which": true, "type": true, "cat": true, "less": true,
	"grep": true, "rg": true, "ls": true, "file": true, "stat": true,
	"apt": true, "apt-get": true, "dnf": true, "yum": true, "apk": true,
	"brew": true, "go": true, "pip": true, "pip3": true, "gem": true,
	"rm": true, "cp": true, "mv": true, "echo": true, "printf": true,
}

// wrapperCommands are the words a command may start with and still be the
// command they wrap: "sudo nmap …" is a scanner run, "sudo apt-get install nmap"
// is not.
var wrapperCommands = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nice": true, "nohup": true,
	"time": true, "xargs": true, "command": true, "timeout": true, "stdbuf": true,
}

// Executor is the exec seam the Observer decorates: the shape of the session's
// shell and code runners (§5.2 of the spec), satisfied by the container session
// and by a test's fake.
type Executor interface {
	// Shell runs a shell command in the session container.
	Shell(ctx context.Context, command string) (string, error)
	// Code runs a snippet in a language runtime present in the container.
	Code(ctx context.Context, lang, code string) (string, error)
}

// Observer decorates an exec runner so the harness sees a scanner run and the
// artifacts it leaves behind (§4). The artifact watch is the reliable backstop;
// the argv sniff is what attributes a run whose output the watch cannot see.
// It never gates anything: an obligation is advisory, and the command runs
// exactly as it would without the observer.
type Observer struct {
	// Inner is the runner the call is forwarded to.
	Inner Executor
	// Tracker records what the run revealed.
	Tracker *Tracker
}

// Shell runs the command and then notes what it may have produced.
func (o Observer) Shell(ctx context.Context, command string) (string, error) {
	out, err := o.Inner.Shell(ctx, command)
	if o.Tracker != nil {
		o.Tracker.NoteCommand(command)
		o.Tracker.Reconcile()
	}
	return out, err
}

// Code runs the snippet and then looks for artifacts it may have written: a
// script that shells out to a scanner is exactly the case argv sniffing misses.
func (o Observer) Code(ctx context.Context, lang, code string) (string, error) {
	out, err := o.Inner.Code(ctx, lang, code)
	if o.Tracker != nil {
		o.Tracker.Reconcile()
	}
	return out, err
}

// Obligation is one pending-parse obligation (§4): a scanner run whose output
// has not been parsed, or an artifact that nothing has parsed yet.
type Obligation struct {
	// Artifact is the artifact as a workspace-relative path, empty for a run
	// whose artifact has not been seen.
	Artifact string
	// Parser is the parser tool expected to read it, empty when the origin is
	// unknown (an artifact nothing here recognizes).
	Parser string
	// Scanner is the scanner the argv sniff attributed it to, empty when the
	// artifact watch found it.
	Scanner string
	// Detected is when the harness noticed it.
	Detected time.Time
}

// Tracker holds the engagement's pending-parse obligations (§4). It is safe for
// concurrent use: the loop's digest, the status bar, and the exec path all
// touch it.
//
// The obligation is advisory and never a block: the loop keeps running, a
// scanner may run again, and an ignored obligation simply leaves state without
// those findings — which the digest makes visible, and that is the control.
type Tracker struct {
	// workspace is the project root artifacts are watched under.
	workspace string
	// now is the clock, injectable for tests.
	now func() time.Time

	mu sync.Mutex
	// artifacts are the obligations the artifact watch found, keyed by the
	// artifact's absolute path: durable until the artifact is parsed or gone.
	artifacts map[string]*Obligation
	// runs are the obligations argv sniffing found, keyed by scanner:
	// one-turn directives, because a run is only detectable when it happens.
	runs map[string]*Obligation
	// parsed stamps the artifacts this tracker has seen parsed, keyed by
	// absolute path. An artifact stays on disk after its parse — it is
	// evidence — so the watch needs this to tell "already read" from "new":
	// a file whose stamp has not moved since its parse is not a new
	// obligation, and one rewritten after its parse is (the scan ran again).
	parsed map[string]fileStamp
	// revision counts every change to the obligation set, so the digest can
	// tell whether it needs re-appending; surfaced is the revision the last
	// digest carried.
	revision int
	surfaced int
}

// NewTracker starts a tracker for a project root. The workspace is the same
// root the parser tools confine their paths to.
func NewTracker(workspace string) *Tracker {
	return &Tracker{
		workspace: workspace,
		now:       time.Now,
		artifacts: map[string]*Obligation{},
		runs:      map[string]*Obligation{},
		parsed:    map[string]fileStamp{},
	}
}

// fileStamp identifies one written version of an artifact: its size and
// modification time. Two reads with the same stamp are the same artifact.
type fileStamp struct {
	// size is the artifact's byte length.
	size int64
	// modified is its modification time, to the nanosecond.
	modified int64
}

// stampOf reads a file's current stamp. ok is false when the file cannot be
// stat'ed, which the caller reads as "not the version I know".
func stampOf(path string) (fileStamp, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, false
	}
	return fileStamp{size: info.Size(), modified: info.ModTime().UnixNano()}, true
}

// WithClock replaces the tracker's clock. Tests pin it.
func (t *Tracker) WithClock(now func() time.Time) *Tracker {
	if now != nil {
		t.now = now
	}
	return t
}

// Workspace is the project root the tracker watches.
func (t *Tracker) Workspace() string { return t.workspace }

// ArtifactsDir is the absolute path of the designated artifact directory.
func (t *Tracker) ArtifactsDir() string { return filepath.Join(t.workspace, ArtifactDir) }

// NoteCommand records a scanner run a shell command's argv reveals (§4). It is
// best-effort: the artifact watch is the reliable backstop, and the sniff exists
// to attribute which parser is expected and to nudge when the output went
// somewhere the watch cannot see.
func (t *Tracker) NoteCommand(command string) {
	scanner, parser, ok := sniffCommand(command)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, known := t.runs[scanner]; known {
		return
	}
	t.runs[scanner] = &Obligation{
		Parser:   parser,
		Scanner:  scanner,
		Detected: t.now().UTC(),
	}
	t.revision++
}

// Reconcile scans the designated artifact directory: a new artifact becomes an
// obligation, and an obligation whose artifact is gone is cleared — the
// artifact's removal is the operator's act, and their waiver of the obligation
// (§4). It is called before a digest is rendered and before the status bar
// reads the count, so detection needs no filesystem watch of its own.
func (t *Tracker) Reconcile() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reconcileLocked()
}

// reconcileLocked is Reconcile's body, with the lock already held.
func (t *Tracker) reconcileLocked() {
	entries, err := os.ReadDir(t.ArtifactsDir())
	if err != nil {
		// No directory yet (nothing scanned), or one this session cannot read:
		// either way there is nothing to add, and the removal pass below still
		// clears an obligation whose artifact is gone.
		entries = nil
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(t.ArtifactsDir(), entry.Name())
		seen[path] = true
		if _, known := t.artifacts[path]; known {
			continue
		}
		if stamp, known := t.parsed[path]; known {
			// Already parsed and unchanged since: the harness read this
			// version, and re-nudging every turn would train the model to
			// ignore the directive.
			if current, ok := stampOf(path); ok && current == stamp {
				continue
			}
			delete(t.parsed, path)
		}
		display, relErr := filepath.Rel(t.workspace, path)
		if relErr != nil {
			display = path
		}
		parser, scanner := sniffArtifact(path)
		t.artifacts[path] = &Obligation{
			Artifact: filepath.ToSlash(display),
			Parser:   parser,
			Scanner:  scanner,
			Detected: t.now().UTC(),
		}
		t.revision++
	}
	for path := range t.artifacts {
		if seen[path] {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			continue
		}
		delete(t.artifacts, path)
		t.revision++
	}
	// A parsed artifact that is gone takes its stamp with it: a path reused
	// later is a new artifact, not a re-read of the old one.
	for path := range t.parsed {
		if _, err := os.Stat(path); err != nil {
			delete(t.parsed, path)
		}
	}
}

// Clear drops the obligation for an artifact a parser has parsed successfully
// (§4): the artifact's own obligation, and any scanner run whose expected
// parser that parse satisfied. path is the artifact's absolute path.
func (t *Tracker) Clear(path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// Remember the version that was parsed, so the watch does not re-open the
	// obligation for the file the parse just read.
	if t.parsed == nil {
		t.parsed = map[string]fileStamp{}
	}
	if stamp, ok := stampOf(abs); ok {
		t.parsed[abs] = stamp
	} else {
		delete(t.parsed, abs)
	}

	parser := ""
	if obligation, known := t.artifacts[abs]; known {
		parser = obligation.Parser
		delete(t.artifacts, abs)
		t.revision++
	}
	if parser == "" {
		// The artifact was never watched (a parser may read any workspace
		// path): the sniff still settles a run waiting on that parser.
		parser, _ = sniffArtifact(abs)
	}
	if parser == "" {
		return
	}
	for scanner, obligation := range t.runs {
		if obligation.Parser == parser {
			delete(t.runs, scanner)
			t.revision++
		}
	}
}

// Pending returns the outstanding obligations for artifacts, oldest first.
func (t *Tracker) Pending() []Obligation {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Obligation, 0, len(t.artifacts))
	for _, obligation := range t.artifacts {
		out = append(out, *obligation)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Detected.Equal(out[j].Detected) {
			return out[i].Detected.Before(out[j].Detected)
		}
		return out[i].Artifact < out[j].Artifact
	})
	return out
}

// Count is how many obligations are outstanding, for the status bar.
func (t *Tracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.artifacts) + len(t.runs)
}

// Due reports whether the obligation set changed since the last digest carried
// it. The digest uses it to re-append itself when an obligation appears or
// clears even though engagement state did not move.
func (t *Tracker) Due() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.revision != t.surfaced
}

// Surfaced marks the current obligation set as carried by a digest. The run
// obligations are one-turn directives: a digest carries them once, and the next
// one does not repeat a run the model has already been told about.
func (t *Tracker) Surfaced() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.surfaced = t.revision
	t.runs = map[string]*Obligation{}
}

// Lines renders the digest's pending-parse block (§4): one
// `pending parse: <artifact> → <parser>` line per artifact, then the directive.
// It is empty when nothing is pending, so a digest that carries no obligation
// says nothing about parsers.
func (t *Tracker) Lines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	pending := make([]string, 0, len(t.artifacts))
	for _, obligation := range t.artifacts {
		pending = append(pending, pendingLine(*obligation))
	}
	sort.Strings(pending)

	runs := make([]string, 0, len(t.runs))
	for _, obligation := range t.runs {
		runs = append(runs, fmt.Sprintf("pending parse: a %s run was detected, no artifact parsed yet → %s",
			obligation.Scanner, obligation.Parser))
	}
	sort.Strings(runs)

	lines := append(pending, runs...)
	if len(lines) == 0 {
		return nil
	}
	if len(lines) > maxPendingLines {
		lines = append(lines[:maxPendingLines], fmt.Sprintf("… %d more pending parse(s)", len(lines)-maxPendingLines))
	}
	return append(lines, "parse scanner output with the matching parser tool: findings reach engagement state only through a parser")
}

// pendingLine renders one artifact obligation.
func pendingLine(obligation Obligation) string {
	if obligation.Parser == "" {
		return fmt.Sprintf("pending parse: %s (no parser recognizes it yet)", obligation.Artifact)
	}
	return fmt.Sprintf("pending parse: %s → %s", obligation.Artifact, obligation.Parser)
}

// sniffCommand looks for a known scanner in a shell command's argv. It splits
// on shell metacharacters, takes each token's base name, and skips a scanner
// word that follows a command that only reads or installs one.
func sniffCommand(command string) (scanner, parser string, ok bool) {
	tokens := strings.FieldsFunc(command, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(";|&()<>=$`\"'", r)
	})
	words := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if word := commandWord(token); word != "" {
			words = append(words, word)
		}
	}
	// The command word is what the command starts with, once its wrappers are
	// set aside. A command that only names or installs a scanner is not a run.
	first := 0
	for first < len(words) && wrapperCommands[words[first]] {
		first++
	}
	if first >= len(words) || nonInvokingCommands[words[first]] {
		return "", "", false
	}
	for _, word := range words[first:] {
		for _, known := range knownScanners {
			for _, alias := range known.argv {
				if word == alias {
					return known.name, known.parser, true
				}
			}
		}
	}
	return "", "", false
}

// commandWord reduces one argv token to the command word it invokes: its base
// name, minus a script extension.
func commandWord(token string) string {
	word := strings.ToLower(strings.TrimSpace(token))
	if word == "" {
		return ""
	}
	word = strings.TrimPrefix(word, "./")
	word = filepath.Base(word)
	for _, suffix := range []string{".exe", ".py", ".sh"} {
		word = strings.TrimSuffix(word, suffix)
	}
	return word
}

// sniffArtifact names the parser an artifact most likely belongs to, by its
// extension and its first lines. It is a hint for the pending-parse line, never
// a validation: the parser itself decides whether it recognizes the artifact,
// and a wrong hint costs one misleading nudge, not a wrong write.
func sniffArtifact(path string) (parser, scanner string) {
	//nolint:gosec // the artifact directory is under the session workspace.
	file, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer func() { _ = file.Close() }()
	head := make([]byte, 4096)
	n, _ := file.Read(head)
	text := string(head[:n])

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".xml":
		if strings.Contains(text, "<nmaprun") {
			return NmapParse, "nmap"
		}
		return "", ""
	case ".jsonl", ".ndjson":
		return NucleiParse, "nuclei"
	case ".json":
		if strings.Contains(text, "\"users\"") || strings.Contains(text, "\"computers\"") ||
			strings.Contains(text, "\"groups\"") || strings.Contains(text, "\"domains\"") {
			return BloodHoundParse, "BloodHound"
		}
		if strings.HasPrefix(strings.TrimSpace(text), "[") {
			return NucleiParse, "nuclei"
		}
		return "", ""
	}
	for _, line := range strings.Split(text, "\n") {
		if patternSQLMapInjectable.MatchString(line) || patternSQLMapHash.MatchString(line) {
			return SQLMapParse, "sqlmap"
		}
		if patternCMETarget.MatchString(line) {
			return CMEParse, "CrackMapExec/NetExec"
		}
		if patternGobusterResult.MatchString(line) {
			return GobusterParse, "gobuster"
		}
		if strings.HasPrefix(strings.TrimSpace(line), "Found: ") {
			return GobusterParse, "gobuster"
		}
	}
	return "", ""
}

// PrepareWorkspace readies a project for artifacts (§3): it creates the
// designated artifact directory, and additively records the gitignore entry
// that keeps scanner output out of the repository. A project that is not a
// repository and has no .gitignore is left alone — there is nothing to ignore.
//
// It is called when an engagement activates, and is idempotent.
func PrepareWorkspace(workspace string) error {
	dir := filepath.Join(workspace, ArtifactDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("parsers: create %s: %w", dir, err)
	}
	return ensureGitignoreEntry(workspace)
}

// ensureGitignoreEntry appends the artifact directory to a project's
// .gitignore when it is not already ignored. An existing entry — in any of the
// spellings that ignore the same path — is left exactly as it is.
func ensureGitignoreEntry(workspace string) error {
	path := filepath.Join(workspace, ".gitignore")
	//nolint:gosec // the path is the project root's own .gitignore.
	existing, err := os.ReadFile(path)
	ignored := false
	content := string(existing)
	if err == nil {
		for _, line := range strings.Split(content, "\n") {
			switch strings.TrimSpace(line) {
			case gitignoreEntry, strings.TrimSuffix(gitignoreEntry, "/"), "/" + gitignoreEntry, "/" + strings.TrimSuffix(gitignoreEntry, "/"):
				ignored = true
			}
		}
		if ignored {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("parsers: read %s: %w", path, err)
	} else if _, statErr := os.Stat(filepath.Join(workspace, ".git")); statErr != nil {
		// No .gitignore and no repository: nothing for the entry to mean.
		return nil
	}

	var b strings.Builder
	b.WriteString(content)
	if content != "" && !strings.HasSuffix(content, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n" + gitignoreNote + "\n" + gitignoreEntry + "\n")
	//nolint:gosec // the path is the project root's own .gitignore.
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("parsers: write %s: %w", path, err)
	}
	return nil
}
