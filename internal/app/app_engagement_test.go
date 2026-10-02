package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/memory"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// appFakeFetcher is the hermetic web_fetch transport for app wiring tests.
type appFakeFetcher struct {
	urls []string
}

func (f *appFakeFetcher) Fetch(_ context.Context, url string) (string, error) {
	f.urls = append(f.urls, url)
	return "fetched " + url, nil
}

// appFakeLogFetcher is the hermetic ssh_logs transport.
type appFakeLogFetcher struct{}

func (appFakeLogFetcher) Logs(context.Context, string, []string) (string, error) {
	return "logs", nil
}

const inSessionEngagement = `apiVersion: styx.engagement/v1
name: in-session
operator: eddy
targets:
  - 192.0.2.44
roe:
  exploit_allowed: true
  destructive_forbidden: true
`

func readAuditRecords(t *testing.T, dir string) []audit.Record {
	t.Helper()
	//nolint:gosec // the audit path is the one the harness wrote in this test.
	data, err := os.ReadFile(filepath.Join(dir, audit.SessionFileName(pinnedNow(t))))
	if err != nil {
		t.Fatalf("read audit trail: %v", err)
	}
	var records []audit.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec audit.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

func TestInSessionEngagementActivationAndTeardown(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "engagement.yaml", inSessionEngagement)
	engPath := filepath.Join(dir, "engagement.yaml")

	fetcher := &appFakeFetcher{}
	fake := fakemodel.New(fakemodel.WithTurns(
		// Safe mode: the out-of-scope... a scope-checked fetch prompts, and the
		// default prompter denies.
		fakemodel.ToolCalls(fakemodel.Call("c1", "web_fetch", `{"url":"http://192.0.2.44/a"}`)),
		fakemodel.Text("safe mode denied"),
		// Engagement mode: in scope, auto-allowed.
		fakemodel.ToolCalls(fakemodel.Call("c2", "web_fetch", `{"url":"http://192.0.2.44/b"}`)),
		fakemodel.Text("engagement fetched"),
		// Back in safe mode: prompts again.
		fakemodel.ToolCalls(fakemodel.Call("c3", "web_fetch", `{"url":"http://192.0.2.44/c"}`)),
		fakemodel.Text("safe again"),
	))
	opts := buildOptions(t, dir, fake)
	opts.Fetcher = fetcher
	opts.LogFetcher = appFakeLogFetcher{}

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// Safe mode: the scope-checked fetch prompts and is denied.
	if err := h.Submit(context.Background(), "fetch"); err != nil {
		t.Fatalf("safe Submit() = %v", err)
	}
	if len(fetcher.urls) != 0 {
		t.Fatalf("safe mode ran a scope-checked fetch without a prompt: %v", fetcher.urls)
	}

	// The in-session door: same gate, scope summary injected, mode engaged.
	out, err := h.command("engagement", engPath)
	if err != nil {
		t.Fatalf("/engagement = %v", err)
	}
	if !strings.Contains(out, "in-session") {
		t.Errorf("/engagement output = %q", out)
	}
	if h.Mode != policy.ModeEngagement {
		t.Fatalf("mode = %q, want engagement", h.Mode)
	}
	if !strings.Contains(h.Prompt, "# Engagement") || !strings.Contains(h.Prompt, "- 192.0.2.44") {
		t.Errorf("scope summary was not injected into the prompt:\n%s", h.Prompt)
	}
	if !strings.Contains(h.statusText(), "engagement: in-session") {
		t.Errorf("/status does not report the engagement:\n%s", h.statusText())
	}

	// In-scope fetch auto-allows with an audit entry.
	if err := h.Submit(context.Background(), "fetch again"); err != nil {
		t.Fatalf("engaged Submit() = %v", err)
	}
	if len(fetcher.urls) != 1 || fetcher.urls[0] != "http://192.0.2.44/b" {
		t.Fatalf("in-scope fetch did not auto-allow: %v", fetcher.urls)
	}

	// The teardown door restores safe mode and removes the scope summary.
	if out, err := h.command("mode", "safe"); err != nil {
		t.Fatalf("/mode safe = %v", err)
	} else if !strings.Contains(out, "safe mode") {
		t.Errorf("/mode safe output = %q", out)
	}
	if h.Mode != policy.ModeSafe || h.Engagement != nil {
		t.Fatalf("after teardown mode = %q, engagement = %v", h.Mode, h.Engagement)
	}
	if strings.Contains(h.Prompt, "# Engagement") {
		t.Errorf("scope summary survived the teardown:\n%s", h.Prompt)
	}

	// Safe-mode verdicts are restored: the fetch prompts and is denied again.
	if err := h.Submit(context.Background(), "fetch once more"); err != nil {
		t.Fatalf("post-teardown Submit() = %v", err)
	}
	if len(fetcher.urls) != 1 {
		t.Errorf("a post-teardown fetch ran without a prompt: %v", fetcher.urls)
	}

	// Engagement end appended structured notes to STYX.md.
	mem, err := memory.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Engagement notes", "- engagement: in-session", "- targets: 192.0.2.44"} {
		if !strings.Contains(mem, want) {
			t.Errorf("STYX.md is missing %q:\n%s", want, mem)
		}
	}

	// Audit trail: deny in safe mode, in-scope allow while engaged, deny after.
	records := readAuditRecords(t, dir)
	var verdicts []audit.Record
	for _, rec := range records {
		if rec.Tool == "web_fetch" {
			verdicts = append(verdicts, rec)
		}
	}
	if len(verdicts) != 3 {
		t.Fatalf("web_fetch audit records = %d, want 3: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Verdict != audit.VerdictDeny {
		t.Errorf("safe-mode verdict = %q, want deny", verdicts[0].Verdict)
	}
	if verdicts[1].Verdict != audit.VerdictAllow || verdicts[1].Reason != string(policy.ReasonInScope) {
		t.Errorf("engaged verdict = %q/%s, want allow/in-scope", verdicts[1].Verdict, verdicts[1].Reason)
	}
	if verdicts[1].Mode != audit.ModeEngagement {
		t.Errorf("engaged audit mode = %q, want engagement", verdicts[1].Mode)
	}
	if verdicts[2].Verdict != audit.VerdictDeny {
		t.Errorf("post-teardown verdict = %q, want deny", verdicts[2].Verdict)
	}
}

func TestBothEngagementDoorsRunTheSameGate(t *testing.T) {
	good := inSessionEngagement
	bad := "apiVersion: styx.engagement/v2\nname: broken\ntargets:\n  - 192.0.2.44\nroe:\n  exploit_allowed: true\n  destructive_forbidden: true\n"

	// Launch door accepts the good file and refuses the bad one.
	dir := t.TempDir()
	goodPath := writeFile(t, dir, "engagement.yaml", good)
	launch, err := Build(context.Background(), func() Options {
		o := buildOptions(t, dir, fakemodel.New())
		o.Engagement = goodPath
		return o
	}())
	if err != nil {
		t.Fatalf("launch door rejected the good file: %v", err)
	}
	if launch.Mode != policy.ModeEngagement {
		t.Errorf("launch door mode = %q, want engagement", launch.Mode)
	}
	_ = launch.Close()

	badDir := t.TempDir()
	badPath := writeFile(t, badDir, "engagement.yaml", bad)
	if _, err := Build(context.Background(), func() Options {
		o := buildOptions(t, badDir, fakemodel.New())
		o.Engagement = badPath
		return o
	}()); err == nil {
		t.Fatal("launch door accepted a malformed file")
	} else if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("launch door error = %v, want the shared validation reason", err)
	}

	// In-session door: the same accept and the same refusal.
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	badSrc := func() string {
		path := writeFile(t, t.TempDir(), "engagement.yaml", bad)
		return path
	}()
	if _, err := h.command("engagement", badSrc); err == nil {
		t.Fatal("/engagement accepted a malformed file")
	} else if !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("/engagement error = %v, want the shared validation reason", err)
	}

	if _, err := h.command("engagement", goodPath); err != nil {
		t.Fatalf("/engagement rejected the good file: %v", err)
	}
	if h.Mode != policy.ModeEngagement || !strings.Contains(h.Prompt, "# Engagement") {
		t.Errorf("in-session activation did not engage: mode=%q", h.Mode)
	}
}

func TestBothDoorsRefuseStaleExpiry(t *testing.T) {
	stale := `apiVersion: styx.engagement/v1
name: stale
targets:
  - 192.0.2.44
expires: 2020-01-01T00:00:00Z
roe:
  exploit_allowed: true
  destructive_forbidden: true
`
	dir := t.TempDir()
	path := writeFile(t, dir, "engagement.yaml", stale)

	if _, err := Build(context.Background(), func() Options {
		o := buildOptions(t, dir, fakemodel.New())
		o.Engagement = path
		return o
	}()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("launch door error = %v, want a stale-expiry refusal", err)
	}

	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	if _, err := h.command("engagement", path); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("/engagement error = %v, want a stale-expiry refusal", err)
	}
	if _, eng := h.modeAndEngagement(); eng != nil {
		t.Error("a stale engagement file activated anyway")
	}
}

// trackingRuntime is a container runtime that records teardown.
type trackingRuntime struct {
	mu         sync.Mutex
	removed    []string
	netRemoved []string
	closed     int
}

func (r *trackingRuntime) Available(context.Context) error { return nil }

func (r *trackingRuntime) CreateNetwork(context.Context, containerlayer.NetworkRequest) (string, error) {
	return "net-1", nil
}

func (r *trackingRuntime) RemoveNetwork(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.netRemoved = append(r.netRemoved, id)
	return nil
}

func (r *trackingRuntime) CreateContainer(context.Context, containerlayer.ContainerSpec) (string, error) {
	return "ctr-1", nil
}

func (r *trackingRuntime) StartContainer(context.Context, string) error { return nil }

func (r *trackingRuntime) Exec(context.Context, string, containerlayer.ExecRequest) (containerlayer.ExecResult, error) {
	return containerlayer.ExecResult{Stdout: "hi\n"}, nil
}

func (r *trackingRuntime) RemoveContainer(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = append(r.removed, id)
	return nil
}

func (r *trackingRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	return nil
}

func TestModeTeardownClosesTheEngagementContainer(t *testing.T) {
	dir := t.TempDir()
	engPath := writeFile(t, dir, "engagement.yaml", inSessionEngagement)

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "bash", `{"command":"echo hi"}`)),
		fakemodel.Text("ran"),
	))
	rt := &trackingRuntime{}
	opts := buildOptions(t, dir, fake)
	opts.Engagement = engPath
	opts.ContainerRuntime = func() (containerlayer.Runtime, error) { return rt, nil }
	opts.ContainerFirewall = appFakeFirewall{}

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	// Allow the exec prompt so the session container actually starts.
	h.setPromptUI(func(msg tui.PromptMsg) {
		if msg.Prompt.Kind == tui.PromptPermission {
			msg.Reply(tui.ChoiceAllowOnce)
		}
	})

	if err := h.Submit(context.Background(), "run it"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	if got := h.Status(false).Isolation; got != string(containerlayer.IsolationContainer) {
		t.Fatalf("isolation = %q, want container (the session did not start)", got)
	}

	if _, err := h.command("mode", "safe"); err != nil {
		t.Fatalf("/mode safe = %v", err)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closed == 0 {
		t.Error("the engagement container runtime was not closed at teardown")
	}
	if len(rt.removed) == 0 || len(rt.netRemoved) == 0 {
		t.Errorf("the session container/network were not torn down: containers=%v networks=%v", rt.removed, rt.netRemoved)
	}
}

// pinnedNow mirrors buildOptions' pinned clock for audit file naming.
func pinnedNow(t *testing.T) (at time.Time) {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
