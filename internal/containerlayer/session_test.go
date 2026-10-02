package containerlayer

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func enforcedOptions(rt Runtime, fw Firewall) SessionOptions {
	return SessionOptions{
		Runtime:   rt,
		Name:      "test-session",
		Allowed:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		Firewall:  fw,
		ProxyAddr: "127.0.0.1:0",
	}
}

func TestStartSessionEnforcedProgramsFirewall(t *testing.T) {
	rt := newFakeRuntime()
	fw := &fakeFirewall{}
	opts := enforcedOptions(rt, fw)
	opts.Workspace = t.TempDir()

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Isolation() != IsolationContainer {
		t.Errorf("isolation = %q, want container", s.Isolation())
	}
	if len(fw.applied) != 1 || fw.applied[0].Bridge != s.Bridge() {
		t.Errorf("firewall applied = %+v, want one spec scoped to %s", fw.applied, s.Bridge())
	}
	if s.ProxyURL() != "" {
		t.Errorf("proxy = %q, want none when egress is enforced at the host edge", s.ProxyURL())
	}

	specs := rt.containerSpecs()
	if len(specs) != 1 {
		t.Fatalf("containers = %d, want 1", len(specs))
	}
	if specs[0].NetworkID == "" || specs[0].NetworkID == "bridge" || specs[0].NetworkID == "host" {
		t.Errorf("container network = %q, want the session network, never default bridge or host", specs[0].NetworkID)
	}
}

func TestStartSessionDegradesWhenNoFirewall(t *testing.T) {
	rt := newFakeRuntime()
	opts := enforcedOptions(rt, nil)
	opts.FirewallRunner = &fakeRunner{available: map[string]bool{}}

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Isolation() != IsolationDegraded {
		t.Fatalf("isolation = %q, want degraded", s.Isolation())
	}
	if s.ProxyURL() == "" {
		t.Error("degraded session has no egress proxy URL")
	}
	// The degraded network must be internal: no external route at all.
	for _, req := range rt.networks {
		if !req.Internal {
			t.Errorf("degraded network = %+v, want internal", req)
		}
	}
	specs := rt.containerSpecs()
	if len(specs) != 1 {
		t.Fatalf("containers = %d, want 1", len(specs))
	}
	if !hasEnvPrefix(specs[0].Env, "HTTP_PROXY=") || !hasEnvPrefix(specs[0].Env, "HTTPS_PROXY=") {
		t.Errorf("degraded container env = %v, want the proxy settings", specs[0].Env)
	}
}

func TestStartSessionDegradesWhenApplyFails(t *testing.T) {
	rt := newFakeRuntime()
	opts := enforcedOptions(rt, &fakeFirewall{failApply: true})

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Isolation() != IsolationDegraded {
		t.Fatalf("isolation = %q, want degraded when the firewall cannot program", s.Isolation())
	}
}

func TestStartSessionRefusesWhenDegradedUnavailable(t *testing.T) {
	rt := newFakeRuntime()
	rt.createNetworkErr = func(req NetworkRequest) error {
		if req.Internal {
			return errors.New("cannot create internal network")
		}
		return nil
	}
	opts := enforcedOptions(rt, nil)
	opts.FirewallRunner = &fakeRunner{available: map[string]bool{}}

	if _, err := StartSession(context.Background(), opts); err == nil {
		t.Fatal("StartSession() = nil error, want a refusal when neither enforcement nor degradation is possible")
	}
	networks, containers := rt.snapshot()
	if networks != 0 || containers != 0 {
		t.Errorf("refused session left %d networks and %d containers, want none", networks, containers)
	}
}

func TestSessionTeardownLeavesNoResidue(t *testing.T) {
	rt := newFakeRuntime()
	fw := &fakeFirewall{}

	for i := 0; i < 2; i++ {
		s, err := StartSession(context.Background(), enforcedOptions(rt, fw))
		if err != nil {
			t.Fatalf("StartSession(%d) = %v", i, err)
		}
		if networks, containers := rt.snapshot(); networks != 1 || containers != 1 {
			t.Fatalf("session %d brought up %d networks and %d containers, want 1 each", i, networks, containers)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close(%d) = %v", i, err)
		}
		if networks, containers := rt.snapshot(); networks != 0 || containers != 0 {
			t.Fatalf("session %d left %d networks and %d containers after teardown, want none", i, networks, containers)
		}
	}
	if len(fw.removed) != 2 {
		t.Errorf("firewall Remove calls = %d, want 2 (one per session)", len(fw.removed))
	}
	if rt.closed {
		// The session does not own the runtime; the manager closes it.
		t.Error("session closed the shared runtime")
	}
}

func TestContainerSpecNeverMountsDockerSocket(t *testing.T) {
	for _, bind := range []string{
		"/var/run/docker.sock:/var/run/docker.sock",
		"/run/docker.sock:/sock/docker.sock",
	} {
		spec := ContainerSpec{Image: "img", NetworkID: "net", Binds: []string{bind}}
		if err := validateContainerSpec(spec); !errors.Is(err, ErrDockerSocketBind) {
			t.Errorf("validateContainerSpec(%q) = %v, want ErrDockerSocketBind", bind, err)
		}
	}
	ok := ContainerSpec{Image: "img", NetworkID: "net", Binds: []string{"/host/project:/workspace"}}
	if err := validateContainerSpec(ok); err != nil {
		t.Errorf("validateContainerSpec(workspace bind) = %v, want nil", err)
	}
}

func TestLangCommandDefaultsToPython3(t *testing.T) {
	for _, lang := range []string{"", "python", "python3"} {
		cmd, err := langCommand(lang, "print(1)")
		if err != nil || len(cmd) != 3 || cmd[0] != "python3" || cmd[1] != "-c" {
			t.Errorf("langCommand(%q) = %v/%v, want python3 -c", lang, cmd, err)
		}
	}
	if _, err := langCommand("brainfuck", "++"); err == nil {
		t.Error("langCommand(unsupported) = nil error, want a clear refusal")
	}
	if _, err := langCommand("python3", ""); err == nil {
		t.Error("langCommand(empty code) = nil error, want a refusal")
	}
	cmd, err := langCommand("go", "package main")
	if err != nil {
		t.Fatalf("langCommand(go) = %v", err)
	}
	if cmd[0] != "sh" || !strings.Contains(strings.Join(cmd, " "), "base64 -d") {
		t.Errorf("langCommand(go) = %v, want the base64 temp-file script", cmd)
	}
}

func TestFormatExecResultSurfacesExitCode(t *testing.T) {
	got := formatExecResult(ExecResult{Stdout: "hello\n", ExitCode: 0})
	if got != "hello" {
		t.Errorf("formatExecResult(ok) = %q, want trimmed stdout", got)
	}
	got = formatExecResult(ExecResult{Stdout: "boom", Stderr: "warn\n", ExitCode: 2})
	if !strings.Contains(got, "boom") || !strings.Contains(got, "warn") || !strings.Contains(got, "[exit code 2]") {
		t.Errorf("formatExecResult(fail) = %q, want output plus the exit status", got)
	}
	if got := formatExecResult(ExecResult{}); got != "(no output)" {
		t.Errorf("formatExecResult(empty) = %q", got)
	}
}

func TestStartSessionServesPinnedNames(t *testing.T) {
	rt := newFakeRuntime()
	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.DNSAddr = "127.0.0.1:0"
	opts.Pins = []NamePin{{Name: "app.acme.example", Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.44")}}}

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	if s.DNSAddr() == "" {
		t.Fatal("harness resolver did not start")
	}
	specs := rt.containerSpecs()
	if len(specs) != 1 || len(specs[0].DNS) != 1 {
		t.Fatalf("container specs = %+v, want the harness resolver configured as DNS", specs)
	}

	// Teardown stops the resolver and is idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() = %v, want idempotence", err)
	}
}

func hasEnvPrefix(env []string, prefix string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}
