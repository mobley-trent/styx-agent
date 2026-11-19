package diffscope

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mobley-trent/styx-agent/internal/apispec"
	"github.com/mobley-trent/styx-agent/internal/engagement"
)

// Options is one diff-scope computation: the project, the base ref the operator
// named, and the engagement whose pool the change narrows.
type Options struct {
	// Root is the project root the run would scan.
	Root string
	// Base is the ref as the operator gave it. It is resolved to its
	// merge-base with HEAD, so base-branch drift since the fork cannot enter.
	Base string
	// Engagement is the active engagement. A diff scope has no meaning without
	// one, so a nil engagement is a refusal.
	Engagement *engagement.Engagement
	// Resolver pins a declared hostname. Nil means the host resolver.
	Resolver apispec.Resolver
}

// Result is what a change declares, narrowed to the engagement's pool.
type Result struct {
	// Base is the ref as the operator gave it, and BaseCommit the merge-base it
	// resolved to.
	Base       string
	BaseCommit string
	// Documents are the changed files that carried a declaration format, in
	// diff order.
	Documents []string
	// Targets are the usable declared hosts, intersected with the pool. An
	// empty list is the successful no-op, never a full-scope run.
	Targets []engagement.Target
	// Changed are the operations the diff added, removed, or edited on the
	// narrowed hosts, as "POST /users/{id}". They are run context and
	// authorize nothing.
	Changed []string
	// Notes name what contributed nothing and why: a refused server, a deleted
	// declaration, a Postman environment file, an unreadable base version.
	Notes []string
}

// Empty reports whether the change maps to no authorized target. It is the
// §11.2 no-op: exit clean, scan nothing.
func (r Result) Empty() bool { return len(r.Targets) == 0 }

// ShortBase is the merge-base commit abbreviated for the identity line.
func (r Result) ShortBase() string {
	if len(r.BaseCommit) <= 12 {
		return r.BaseCommit
	}
	return r.BaseCommit[:12]
}

// TargetNames renders the effective pool for a one-line report.
func (r Result) TargetNames() []string {
	out := make([]string, 0, len(r.Targets))
	for _, target := range r.Targets {
		out = append(out, target.Host)
	}
	return out
}

// git runs one git command in root and returns its stdout. It is the package's
// single shell-out seam, so a test can drive the computation without a
// repository.
var git = func(ctx context.Context, root string, args ...string) ([]byte, error) {
	//nolint:gosec // git and the project root are the operator's own tooling and checkout; args are fixed subcommands.
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, errors.New(detail)
	}
	return out, nil
}

// Compute reads the change from base to HEAD and returns the targets it
// declares, narrowed by the engagement's pool. A ref that will not resolve, a
// project that is not a repository, and a changed declaration that will not
// load are all refusals: each names what failed, and none falls back to full
// scope.
func Compute(ctx context.Context, opts Options) (Result, error) {
	base := strings.TrimSpace(opts.Base)
	if base == "" {
		return Result{}, errors.New("diff scope: a base ref is required")
	}
	if opts.Engagement == nil {
		return Result{}, errors.New("diff scope: no engagement is active, so a change has no pool to narrow")
	}
	root := strings.TrimSpace(opts.Root)
	if root == "" {
		return Result{}, errors.New("diff scope: a project root is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Result{}, fmt.Errorf("diff scope: resolve %s: %w", opts.Root, err)
	}

	result := Result{Base: base}

	// The base is explicit and resolved: the merge-base with HEAD is the
	// three-dot, PR-shaped comparison, so a base branch that moved since the
	// fork cannot enter the diff. A ref that will not resolve refuses the run
	// rather than falling back to a default or to full scope.
	raw, err := git(ctx, root, "merge-base", base, "HEAD")
	if err != nil {
		return Result{}, fmt.Errorf("diff scope: base %q: %w", base, err)
	}
	result.BaseCommit = strings.TrimSpace(string(raw))
	if result.BaseCommit == "" {
		return Result{}, fmt.Errorf("diff scope: base %q: no merge-base with HEAD", base)
	}

	prefix, err := git(ctx, root, "rev-parse", "--show-prefix")
	if err != nil {
		return Result{}, fmt.Errorf("diff scope: %s is not a git repository: %w", root, err)
	}
	projectPrefix := strings.TrimSpace(string(prefix))

	raw, err = git(ctx, root, "diff", "--name-status", "-z", "-M", result.BaseCommit, "HEAD", "--")
	if err != nil {
		return Result{}, fmt.Errorf("diff scope: diff %s..HEAD: %w", result.BaseCommit, err)
	}

	declared := newDeclarations(ctx, root, result.BaseCommit, opts)
	for _, ch := range parseNameStatus(raw) {
		if err := declared.consider(ch, projectPrefix); err != nil {
			return Result{}, err
		}
	}
	return declared.result(result), nil
}

// declarations accumulates one computation's findings as the diff is walked.
type declarations struct {
	ctx        context.Context
	root       string
	mergeBase  string
	engagement *engagement.Engagement
	resolver   apispec.Resolver

	// hosts maps each usable declared host to the addresses it resolved to.
	hosts map[string]map[netip.Addr]bool
	// changed holds every operation the diff touched, with the host it is
	// declared under.
	changed []changedOperation
	docs    []string
	notes   []string
}

// changedOperation is one operation the diff touched, before the narrowed hosts
// are known.
type changedOperation struct {
	key  string
	host string
}

func newDeclarations(ctx context.Context, root, mergeBase string, opts Options) *declarations {
	return &declarations{
		ctx:        ctx,
		root:       root,
		mergeBase:  mergeBase,
		engagement: opts.Engagement,
		resolver:   opts.Resolver,
		hosts:      map[string]map[netip.Addr]bool{},
	}
}

// consider decides what one changed path contributes: a declaration is loaded,
// a Postman environment file or a document with no format key contributes
// nothing, and a declaration that will not load refuses the run.
func (d *declarations) consider(ch change, projectPrefix string) error {
	repoPath := ch.new
	if ch.status == "D" {
		repoPath = ch.old
	}
	rel, inside := projectPath(repoPath, projectPrefix)
	if !inside {
		d.notes = append(d.notes, fmt.Sprintf("%s: outside the project root; contributes nothing", repoPath))
		return nil
	}

	if ch.status == "D" {
		// A deleted document declares nothing for this run, but a deleted
		// declaration is named rather than dropped silently.
		if data, err := git(d.ctx, d.root, "show", d.mergeBase+":"+repoPath); err == nil && apispec.FormatKey(data) {
			d.notes = append(d.notes, fmt.Sprintf("%s: deleted; a deleted declaration contributes nothing", rel))
		}
		return nil
	}

	if !declarationExtension(rel) {
		return nil
	}
	//nolint:gosec // the path was confined to the project root above.
	data, err := os.ReadFile(filepath.Join(d.root, rel))
	if err != nil {
		return fmt.Errorf("diff scope: %s: read the changed declaration: %w", rel, err)
	}
	if !apispec.FormatKey(data) {
		if isPostmanEnvironment(data) {
			d.notes = append(d.notes, fmt.Sprintf("%s: a Postman environment file declares no server; contributes nothing", rel))
		}
		return nil
	}

	newDecl, err := d.declare(rel, data)
	if err != nil {
		// A scope flag is an assurance, and it must not claim one the run
		// cannot keep: a declaration it could not read is a refusal, never a
		// silent skip (§5.2). The loader's refusal already names the file and
		// the parse error.
		return fmt.Errorf("diff scope: %w", err)
	}
	d.docs = append(d.docs, rel)
	d.record(rel, ch.old, newDecl)
	return nil
}

// declare loads one candidate through the same loader the tool uses, harness
// side and with nothing to write.
func (d *declarations) declare(artifact string, data []byte) (apispec.Declaration, error) {
	return apispec.Declare(d.ctx, apispec.DeclareRequest{
		Artifact: artifact,
		Data:     data,
		Scope:    d.engagement.Scope(),
		Resolver: d.resolver,
		Pool:     d.engagement.Targets(),
	})
}

// record takes what the new declaration contributes and diffs its operations
// against the base version's.
func (d *declarations) record(rel, oldRepoPath string, newDecl apispec.Declaration) {
	if newDecl.NoServer != "" {
		d.notes = append(d.notes, fmt.Sprintf("%s: %s; contributes nothing", rel, newDecl.NoServer))
	}
	for _, server := range newDecl.Refused() {
		name := server.Host
		if name == "" {
			name = server.URL
		}
		d.notes = append(d.notes, fmt.Sprintf("%s: refused %s: %s", rel, name, server.Reason))
	}
	for _, server := range newDecl.Usable() {
		addrs := d.hosts[server.Host]
		if addrs == nil {
			addrs = map[netip.Addr]bool{}
			d.hosts[server.Host] = addrs
		}
		for _, addr := range server.Addresses {
			addrs[addr.Unmap()] = true
		}
	}

	var oldDecl apispec.Declaration
	haveOld := false
	if oldRepoPath != "" {
		blob, err := git(d.ctx, d.root, "show", d.mergeBase+":"+oldRepoPath)
		if err != nil {
			d.notes = append(d.notes, fmt.Sprintf("%s: the base version could not be read (%s); its operations are unknown", rel, err))
		} else if decl, err := d.declare(rel+"@"+shortCommit(d.mergeBase), blob); err != nil {
			// The tree's declarations are readable, which is what the run is
			// narrowed from; a base version that will not load is named rather
			// than mistaken for an empty document.
			d.notes = append(d.notes, fmt.Sprintf("%s: the base version does not load (%s); its operations are unknown", rel, err))
		} else {
			oldDecl, haveOld = decl, true
		}
	}
	d.changed = append(d.changed, changedOperations(oldDecl, haveOld, newDecl)...)
}

// result narrows the accumulated declarations and renders the computation's
// outcome.
func (d *declarations) result(base Result) Result {
	base.Documents = d.docs
	base.Notes = d.notes

	hosts := make([]string, 0, len(d.hosts))
	for host := range d.hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	narrowed := map[string]bool{}
	for _, host := range hosts {
		var addrs []netip.Addr
		for addr := range d.hosts[host] {
			addrs = append(addrs, addr)
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
		base.Targets = append(base.Targets, engagement.Target{Host: host, Addrs: addrs})
		narrowed[host] = true
	}

	seen := map[string]bool{}
	for _, op := range d.changed {
		if op.key == "" || seen[op.key] || !narrowed[op.host] {
			continue
		}
		seen[op.key] = true
		base.Changed = append(base.Changed, op.key)
	}
	return base
}

// changedOperations reports the operations the diff added, removed, or edited:
// a key absent from either side, or present on both with a different
// declaration, is changed. A removed operation keeps the host it was declared
// under, so it still reports when that host stays in scope.
func changedOperations(oldDecl apispec.Declaration, haveOld bool, newDecl apispec.Declaration) []changedOperation {
	oldOps := map[string]apispec.InventoryOperation{}
	for _, op := range oldDecl.Operations {
		oldOps[operationKey(op)] = op
	}

	var out []changedOperation
	seen := map[string]bool{}
	for _, op := range newDecl.Operations {
		key := operationKey(op)
		prev, existed := oldOps[key]
		seen[key] = true
		if existed && prev.Fingerprint == op.Fingerprint {
			continue
		}
		out = append(out, changedOperation{key: key, host: operationHost(op)})
	}
	if haveOld {
		var removed []changedOperation
		for key, op := range oldOps {
			if seen[key] {
				continue
			}
			removed = append(removed, changedOperation{key: key, host: operationHost(op)})
		}
		sort.Slice(removed, func(i, j int) bool { return removed[i].key < removed[j].key })
		out = append(out, removed...)
	}
	return out
}

// operationKey renders an operation as the run's context names it.
func operationKey(op apispec.InventoryOperation) string {
	if op.Method == "" || op.Path == "" {
		return ""
	}
	return op.Method + " " + op.Path
}

// operationHost is the host of the server an operation is declared under.
func operationHost(op apispec.InventoryOperation) string {
	parsed, err := url.Parse(op.Server)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// declarationExtension reports whether a path's extension is one a declaration
// can have. Extension alone never makes a declaration (§5.1); it is the cheap
// half of the test.
func declarationExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".yaml", ".yml":
		return true
	}
	return false
}

// projectPath reduces a repo-relative path to the project root's view of it,
// and reports whether it lies inside the project at all.
func projectPath(repoPath, prefix string) (string, bool) {
	if prefix == "" {
		return repoPath, repoPath != ""
	}
	rel, ok := strings.CutPrefix(repoPath, prefix)
	if !ok || rel == "" {
		return "", false
	}
	return rel, true
}

// isPostmanEnvironment reports whether a document is a Postman environment
// export: a changed one declares no server, and it is where the secrets are
// (§5.1, §3.4). It is named rather than silently dropped.
func isPostmanEnvironment(data []byte) bool {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil || doc == nil {
		return false
	}
	if scope, ok := doc["_postman_variable_scope"].(string); ok && strings.EqualFold(scope, "environment") {
		return true
	}
	_, hasValues := doc["values"]
	_, hasName := doc["name"]
	_, hasID := doc["id"]
	return hasValues && hasName && hasID
}

// change is one path the diff touched.
type change struct {
	status string
	old    string
	new    string
}

// parseNameStatus reads `git diff --name-status -z` output. A rename or copy
// carries two paths; every other status carries one.
func parseNameStatus(out []byte) []change {
	fields := bytes.Split(out, []byte{0})
	var changes []change
	for i := 0; i < len(fields); {
		status := strings.TrimSpace(string(fields[i]))
		if status == "" {
			i++
			continue
		}
		letter := status[:1]
		switch letter {
		case "R", "C":
			if i+2 >= len(fields) {
				return changes
			}
			changes = append(changes, change{status: letter, old: string(fields[i+1]), new: string(fields[i+2])})
			i += 3
		default:
			if i+1 >= len(fields) {
				return changes
			}
			path := string(fields[i+1])
			ch := change{status: letter, new: path}
			if letter != "A" {
				ch.old = path
			}
			changes = append(changes, ch)
			i += 2
		}
	}
	return changes
}

// shortCommit abbreviates a commit for a note about a base-version read.
func shortCommit(commit string) string {
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}
