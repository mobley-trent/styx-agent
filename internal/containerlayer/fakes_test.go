package containerlayer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// fakeRuntime is an in-memory Runtime that records what the session asked of
// it, so orchestration and teardown are assertable without a Docker daemon.
type fakeRuntime struct {
	mu sync.Mutex

	availableErr error
	// createNetworkErr lets a test fail network creation (e.g. the internal
	// network in degraded mode).
	createNetworkErr func(req NetworkRequest) error

	networks          map[string]NetworkRequest
	containers        map[string]ContainerSpec
	removedNetworks   []string
	removedContainers []string
	execs             []ExecRequest
	execResult        ExecResult
	execErr           error
	// ensureImageErr fails image availability; ensuredImages records what was
	// asked for, so the StartSession wiring is assertable.
	ensureImageErr error
	ensuredImages  []string
	closed         bool
	nextID         int
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		networks:   map[string]NetworkRequest{},
		containers: map[string]ContainerSpec{},
	}
}

func (r *fakeRuntime) id(prefix string) string {
	r.nextID++
	return fmt.Sprintf("%s-%d", prefix, r.nextID)
}

func (r *fakeRuntime) Available(context.Context) error { return r.availableErr }

// EnsureImage implements ImageEnsurer so the session's image-availability step
// runs against the fake.
func (r *fakeRuntime) EnsureImage(_ context.Context, image string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensuredImages = append(r.ensuredImages, image)
	return r.ensureImageErr
}

func (r *fakeRuntime) CreateNetwork(_ context.Context, req NetworkRequest) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.createNetworkErr != nil {
		if err := r.createNetworkErr(req); err != nil {
			return "", err
		}
	}
	id := r.id("net")
	r.networks[id] = req
	return id, nil
}

func (r *fakeRuntime) RemoveNetwork(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.networks, id)
	r.removedNetworks = append(r.removedNetworks, id)
	return nil
}

func (r *fakeRuntime) CreateContainer(_ context.Context, spec ContainerSpec) (string, error) {
	if err := validateContainerSpec(spec); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.id("ctr")
	r.containers[id] = spec
	return id, nil
}

func (r *fakeRuntime) StartContainer(context.Context, string) error { return nil }

func (r *fakeRuntime) Exec(_ context.Context, id string, req ExecRequest) (ExecResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.containers[id]; !ok {
		return ExecResult{}, errors.New("fake: unknown container")
	}
	r.execs = append(r.execs, req)
	return r.execResult, r.execErr
}

func (r *fakeRuntime) RemoveContainer(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.containers, id)
	r.removedContainers = append(r.removedContainers, id)
	return nil
}

func (r *fakeRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *fakeRuntime) snapshot() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.networks), len(r.containers)
}

func (r *fakeRuntime) containerSpecs() []ContainerSpec {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ContainerSpec, 0, len(r.containers))
	for _, spec := range r.containers {
		out = append(out, spec)
	}
	return out
}

// fakeFirewall records Apply and Remove calls, and can fail Apply to force the
// degraded path.
type fakeFirewall struct {
	mu        sync.Mutex
	applied   []EgressSpec
	removed   []EgressSpec
	failApply bool
}

func (f *fakeFirewall) Backend() Backend { return BackendNFT }

func (f *fakeFirewall) Apply(_ context.Context, spec EgressSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failApply {
		return errors.New("fake firewall refused to program")
	}
	f.applied = append(f.applied, spec)
	return nil
}

func (f *fakeFirewall) Remove(_ context.Context, spec EgressSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, spec)
	return nil
}

// fakeRunner answers the firewall's detection probes. Only programs listed in
// available succeed.
type fakeRunner struct {
	mu        sync.Mutex
	available map[string]bool
	calls     [][]string
}

func (r *fakeRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, args)
	if len(args) > 0 && r.available[args[0]] {
		return "", nil
	}
	return "not available", errors.New("command failed")
}

// allowChecker builds a prefix checker for tests.
func allowChecker(entries ...string) func(netip.Addr) bool {
	var prefixes []netip.Prefix
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		if ip, err := netip.ParseAddr(e); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return prefixChecker(prefixes)
}
