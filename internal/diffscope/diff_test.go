package diffscope_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/diffscope"
	"github.com/mobley-trent/styx-agent/internal/engagement"
)

// newRepo is a throwaway repository: local, offline, and configured so a commit
// never asks for an identity.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	gitRun(t, dir, "config", "user.email", "test@example.com")
	gitRun(t, dir, "config", "user.name", "diff scope test")
	gitRun(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

// gitRun runs one git command and fails the test with its output on error.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	//nolint:gosec // the test drives git against its own temporary repository.
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// write puts one file in the repository.
func write(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// commitAll commits the tree and returns the commit.
func commitAll(t *testing.T, dir, message string) string {
	t.Helper()
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", message)
	return gitRun(t, dir, "rev-parse", "HEAD")
}

// engagementFor builds an IP-only engagement, so the computation never touches
// DNS.
func engagementFor(t *testing.T, targets ...string) *engagement.Engagement {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: styx.engagement/v1\nname: diff-scope\noperator: test\ntargets:\n")
	for _, target := range targets {
		b.WriteString("  - " + target + "\n")
	}
	b.WriteString("roe:\n  exploit_allowed: false\n  destructive_forbidden: true\n")
	eng, err := engagement.Parse(context.Background(), []byte(b.String()), engagement.WithClock(func() time.Time {
		return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	}))
	if err != nil {
		t.Fatalf("engagement.Parse() = %v", err)
	}
	return eng
}

const baseSpec = `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://192.0.2.44/v1
paths:
  /users:
    get: {}
`

const changedSpec = `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://192.0.2.44/v1
paths:
  /users:
    get: {}
    post: {}
`

// TestComputeNarrowsToTheChangedSpec covers the PR-shaped case: an operation
// added under an in-scope spec narrows the run to that spec's host and reaches
// it as changed-operation context. Functionality no test would miss.
func TestComputeNarrowsToTheChangedSpec(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "api/openapi.yaml", baseSpec)
	base := commitAll(t, dir, "base")
	write(t, dir, "api/openapi.yaml", changedSpec)
	commitAll(t, dir, "add an operation")

	// The engagement authorizes two things; the change declares one.
	eng := engagementFor(t, "192.0.2.44", "10.9.9.0/24")
	res, err := diffscope.Compute(context.Background(), diffscope.Options{Root: dir, Base: base, Engagement: eng})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if res.Empty() {
		t.Fatal("Compute() matched no target, want the spec's host")
	}
	if names := res.TargetNames(); len(names) != 1 || names[0] != "192.0.2.44" {
		t.Errorf("targets = %v, want [192.0.2.44]", names)
	}
	if len(res.Targets[0].Addrs) != 1 || res.Targets[0].Addrs[0].String() != "192.0.2.44" {
		t.Errorf("target addresses = %v, want [192.0.2.44]", res.Targets[0].Addrs)
	}
	if len(res.Changed) != 1 || res.Changed[0] != "POST /users" {
		t.Errorf("changed = %v, want [POST /users]", res.Changed)
	}
	if len(res.Documents) != 1 || res.Documents[0] != "api/openapi.yaml" {
		t.Errorf("documents = %v, want [api/openapi.yaml]", res.Documents)
	}
	if res.BaseCommit != base {
		t.Errorf("base commit = %q, want %q", res.BaseCommit, base)
	}
	if res.ShortBase() != base[:12] {
		t.Errorf("short base = %q, want %q", res.ShortBase(), base[:12])
	}
	for _, note := range res.Notes {
		if strings.Contains(note, "refused") {
			t.Errorf("note names a refusal for an all-in-scope spec: %q", note)
		}
	}
}

// TestComputeNamesARefusedServer covers §5.3: a spec declaring one
// out-of-scope server narrows to the in-scope one and names the other; when it
// is the only one, the result is the no-op.
func TestComputeNamesARefusedServer(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://192.0.2.44/v1
  - url: https://198.51.100.7/v1
paths:
  /users:
    get: {}
`
	dir := newRepo(t)
	write(t, dir, "api/openapi.yaml", baseSpec)
	base := commitAll(t, dir, "base")
	write(t, dir, "api/openapi.yaml", doc)
	commitAll(t, dir, "declare a second server")

	eng := engagementFor(t, "192.0.2.44")
	res, err := diffscope.Compute(context.Background(), diffscope.Options{Root: dir, Base: base, Engagement: eng})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if names := res.TargetNames(); len(names) != 1 || names[0] != "192.0.2.44" {
		t.Fatalf("targets = %v, want the in-scope server only", names)
	}
	var noted bool
	for _, note := range res.Notes {
		if strings.Contains(note, "198.51.100.7") && strings.Contains(note, "outside engagement targets") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("notes = %v, want the refused server named", res.Notes)
	}

	// The same document, declaring only the out-of-scope server, is the no-op.
	onlyOutside := newRepo(t)
	write(t, onlyOutside, "api/openapi.yaml", baseSpec)
	baseOnly := commitAll(t, onlyOutside, "base")
	write(t, onlyOutside, "api/openapi.yaml", `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://198.51.100.7/v1
paths:
  /users:
    get: {}
`)
	commitAll(t, onlyOutside, "declare only the other server")
	outside, err := diffscope.Compute(context.Background(), diffscope.Options{Root: onlyOutside, Base: baseOnly, Engagement: eng})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if !outside.Empty() {
		t.Fatalf("targets = %v, want the no-op", outside.TargetNames())
	}
}

// TestComputeRefusesABrokenDeclaration covers §5.2: a changed candidate that
// carries a format key and will not load refuses the run, naming the file and
// the parse error.
func TestComputeRefusesABrokenDeclaration(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "api/openapi.yaml", baseSpec)
	base := commitAll(t, dir, "base")
	write(t, dir, "api/openapi.yaml", "openapi: 3.1.0\ninfo:\n  title: Acme\n paths: indented wrong\n")
	commitAll(t, dir, "break the spec")

	_, err := diffscope.Compute(context.Background(), diffscope.Options{
		Root:       dir,
		Base:       base,
		Engagement: engagementFor(t, "192.0.2.44"),
	})
	if err == nil {
		t.Fatal("Compute() = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "api/openapi.yaml") {
		t.Errorf("error = %q, want the file named", err)
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error = %q, want the parse error named", err)
	}
}

// TestComputeSourceOnlyChangeIsTheNoOp covers §5.3: an unchanged document
// contributes nothing, so a source-only diff narrows to nothing.
func TestComputeSourceOnlyChangeIsTheNoOp(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "api/openapi.yaml", baseSpec)
	write(t, dir, "main.go", "package main\n")
	base := commitAll(t, dir, "base")
	write(t, dir, "main.go", "package main\n\nfunc main() {}\n")
	commitAll(t, dir, "touch the source only")

	res, err := diffscope.Compute(context.Background(), diffscope.Options{
		Root:       dir,
		Base:       base,
		Engagement: engagementFor(t, "192.0.2.44"),
	})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if !res.Empty() {
		t.Fatalf("targets = %v, want none for a source-only change", res.TargetNames())
	}
	if len(res.Changed) != 0 {
		t.Errorf("changed = %v, want none", res.Changed)
	}
}

// TestComputeNamesDeletedSpecAndPostmanEnvironment covers the two changes that
// look like declarations and are not: a deleted spec, and a changed Postman
// environment file (where the secrets are).
func TestComputeNamesDeletedSpecAndPostmanEnvironment(t *testing.T) {
	postmanEnv := `{"id": "env-1", "name": "acme", "_postman_variable_scope": "environment", "values": [{"key": "baseUrl", "value": "https://192.0.2.44"}]}`
	dir := newRepo(t)
	write(t, dir, "api/openapi.yaml", baseSpec)
	write(t, dir, "api/acme.postman_environment.json", postmanEnv)
	base := commitAll(t, dir, "base")

	if err := os.Remove(filepath.Join(dir, "api/openapi.yaml")); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "api/acme.postman_environment.json", strings.Replace(postmanEnv, "192.0.2.44", "192.0.2.44/v2", 1))
	commitAll(t, dir, "delete the spec, edit the environment")

	res, err := diffscope.Compute(context.Background(), diffscope.Options{
		Root:       dir,
		Base:       base,
		Engagement: engagementFor(t, "192.0.2.44"),
	})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if !res.Empty() {
		t.Fatalf("targets = %v, want none", res.TargetNames())
	}
	var deleted, environment bool
	for _, note := range res.Notes {
		if strings.Contains(note, "api/openapi.yaml") && strings.Contains(note, "deleted") {
			deleted = true
		}
		if strings.Contains(note, "acme.postman_environment.json") && strings.Contains(note, "Postman environment") {
			environment = true
		}
	}
	if !deleted {
		t.Errorf("notes = %v, want the deleted declaration named", res.Notes)
	}
	if !environment {
		t.Errorf("notes = %v, want the Postman environment file named", res.Notes)
	}
}

// TestComputeRefusesAnUnresolvableBase covers §11.2: a base that will not
// resolve refuses the run, naming the ref, and never falls back to full scope.
func TestComputeRefusesAnUnresolvableBase(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "main.go", "package main\n")
	commitAll(t, dir, "base")

	_, err := diffscope.Compute(context.Background(), diffscope.Options{
		Root:       dir,
		Base:       "no-such-ref",
		Engagement: engagementFor(t, "192.0.2.44"),
	})
	if err == nil {
		t.Fatal("Compute() = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), `base "no-such-ref"`) {
		t.Errorf("error = %q, want the ref named", err)
	}
}

// nameResolver answers the declared names its table holds, so a diff-scope test
// can declare a hostname without touching DNS.
type nameResolver map[string][]string

// LookupHost answers from the table, NXDOMAIN otherwise.
func (r nameResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addrs, ok := r[host]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

const nameSpec = `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
paths:
  /users:
    get: {}
`

const nameSpecChanged = `openapi: 3.1.0
info: {title: Acme, version: "1"}
servers:
  - url: https://api.acme.example/v1
paths:
  /users:
    get: {}
    post: {}
`

// TestComputeKeepsADeclaredNameAuthorizedByCIDR composes the two halves: the
// change narrows to the spec's declared name, and the narrowed pool still
// answers that name — a pool of bare addresses would leave the container unable
// to resolve it, so every request by name would fail.
func TestComputeKeepsADeclaredNameAuthorizedByCIDR(t *testing.T) {
	dir := newRepo(t)
	write(t, dir, "api/openapi.yaml", nameSpec)
	base := commitAll(t, dir, "base")
	write(t, dir, "api/openapi.yaml", nameSpecChanged)
	commitAll(t, dir, "add an operation")

	eng := engagementFor(t, "10.1.0.0/24")
	res, err := diffscope.Compute(context.Background(), diffscope.Options{
		Root:       dir,
		Base:       base,
		Engagement: eng,
		Resolver:   nameResolver{"api.acme.example": {"10.1.0.5"}},
	})
	if err != nil {
		t.Fatalf("Compute() = %v", err)
	}
	if names := res.TargetNames(); len(names) != 1 || names[0] != "api.acme.example" {
		t.Fatalf("targets = %v, want the declared name", names)
	}
	if len(res.Changed) != 1 || res.Changed[0] != "POST /users" {
		t.Errorf("changed = %v, want [POST /users]", res.Changed)
	}

	narrowed := eng.Narrow(res.Targets)
	if !narrowed.Scope().InScope("api.acme.example") {
		t.Fatal("the declared name is not reachable by name after narrowing")
	}
	pins := narrowed.Scope().HostPins()
	if len(pins) != 1 || pins[0].Name != "api.acme.example" {
		t.Fatalf("host pins = %+v, want the declared name", pins)
	}
	if len(pins[0].Addrs) != 1 || pins[0].Addrs[0].String() != "10.1.0.5" {
		t.Errorf("pins = %v, want the declared address", pins[0].Addrs)
	}
	if narrowed.Scope().InScope("10.1.0.6") {
		t.Error("an undeclared address inside the CIDR became reachable")
	}
}
