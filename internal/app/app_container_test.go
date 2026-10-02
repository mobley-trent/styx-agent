package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// appFakeRuntime is a minimal in-memory container engine for app wiring tests.
type appFakeRuntime struct {
	networks   int
	containers []containerlayer.ContainerSpec
	execs      []containerlayer.ExecRequest
	execOutput string
}

func (r *appFakeRuntime) Available(context.Context) error { return nil }

func (r *appFakeRuntime) CreateNetwork(context.Context, containerlayer.NetworkRequest) (string, error) {
	r.networks++
	return "net-1", nil
}

func (r *appFakeRuntime) RemoveNetwork(context.Context, string) error { return nil }

func (r *appFakeRuntime) CreateContainer(_ context.Context, spec containerlayer.ContainerSpec) (string, error) {
	r.containers = append(r.containers, spec)
	return "ctr-1", nil
}

func (r *appFakeRuntime) StartContainer(context.Context, string) error { return nil }

func (r *appFakeRuntime) Exec(_ context.Context, _ string, req containerlayer.ExecRequest) (containerlayer.ExecResult, error) {
	r.execs = append(r.execs, req)
	return containerlayer.ExecResult{Stdout: r.execOutput}, nil
}

func (r *appFakeRuntime) RemoveContainer(context.Context, string) error { return nil }

func (r *appFakeRuntime) Close() error { return nil }

// appFakeFirewall accepts every egress spec, so the session reaches enforced
// isolation deterministically.
type appFakeFirewall struct{}

func (appFakeFirewall) Backend() containerlayer.Backend { return containerlayer.BackendNFT }

func (appFakeFirewall) Apply(context.Context, containerlayer.EgressSpec) error { return nil }

func (appFakeFirewall) Remove(context.Context, containerlayer.EgressSpec) error { return nil }

func TestExecToolRunsInContainerAndSurfacesIsolation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".styx/config.yaml", "permissions:\n  rules:\n    - tool: bash\n      action: allow\n")

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("call-1", "bash", `{"command":"echo hi"}`)),
		fakemodel.Text("done"),
		fakemodel.ToolCalls(fakemodel.Call("call-2", "bash", `{"command":"echo hi"}`)),
		fakemodel.Text("done again"),
	))
	rt := &appFakeRuntime{execOutput: "hi\n"}
	opts := buildOptions(t, dir, fake)
	opts.ContainerRuntime = func() (containerlayer.Runtime, error) { return rt, nil }
	opts.ContainerFirewall = appFakeFirewall{}

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	var events []sessions.Event
	h.setUI(func(ev sessions.Event) { events = append(events, ev) })

	if err := h.Submit(context.Background(), "say hi"); err != nil {
		t.Fatalf("Submit() = %v", err)
	}
	// The first call starts the container; the second, with the container up,
	// is audited under the established isolation level.
	if err := h.Submit(context.Background(), "say hi again"); err != nil {
		t.Fatalf("second Submit() = %v", err)
	}

	if len(rt.containers) != 1 {
		t.Fatalf("containers started = %d, want 1", len(rt.containers))
	}
	if rt.containers[0].NetworkID == "" {
		t.Error("container was created without the session network")
	}
	if len(rt.execs) != 2 || rt.execs[0].Cmd[0] != "sh" {
		t.Fatalf("execs = %+v, want both bash commands dispatched to the container", rt.execs)
	}

	// Isolation is surfaced three ways (§5.2, §9.5): status bar, stream
	// banner, audit record.
	if got := h.Status(false).Isolation; got != string(containerlayer.IsolationContainer) {
		t.Errorf("status isolation = %q, want container", got)
	}
	var banner *sessions.Event
	for i := range events {
		if events[i].Kind == sessions.KindIsolation {
			banner = &events[i]
		}
	}
	if banner == nil || banner.Isolation != string(containerlayer.IsolationContainer) {
		t.Errorf("isolation banner = %+v, want one naming container isolation", banner)
	}

	//nolint:gosec // the audit path is the one the harness wrote in this test.
	data, err := os.ReadFile(filepath.Join(dir, audit.SessionFileName(h.now())))
	if err != nil {
		t.Fatalf("read audit trail: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"bash"`) || !strings.Contains(string(data), `"isolation":"container"`) {
		t.Errorf("audit trail = %s, want the bash call recorded under container isolation", data)
	}
}

func TestExecToolsRegistered(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	names := map[string]bool{}
	for _, name := range h.Tools.Names() {
		names[name] = true
	}
	for _, want := range []string{"bash", "code_exec"} {
		if !names[want] {
			t.Errorf("registry is missing the %q exec tool", want)
		}
	}
}
