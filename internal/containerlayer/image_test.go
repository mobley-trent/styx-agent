package containerlayer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/sandbox"
)

// recordingVerifier records that verification ran, and fails when asked to.
type recordingVerifier struct {
	calls *[]string
	err   error
}

func (v recordingVerifier) VerifyImage(context.Context, string) error {
	*v.calls = append(*v.calls, "verify")
	return v.err
}

// pullRecordingRuntime notes when the image pull step happens, so the ordering
// against verification is assertable.
type pullRecordingRuntime struct {
	*fakeRuntime
	calls *[]string
}

func (r pullRecordingRuntime) EnsureImage(ctx context.Context, ref string) error {
	*r.calls = append(*r.calls, "ensure")
	return r.fakeRuntime.EnsureImage(ctx, ref)
}

// TestStartSessionVerifiesBeforePullingTheImage is the whole point of the seam:
// unverified bytes never reach the daemon, so verification must run first.
func TestStartSessionVerifiesBeforePullingTheImage(t *testing.T) {
	var calls []string
	rt := pullRecordingRuntime{fakeRuntime: newFakeRuntime(), calls: &calls}
	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.Verifier = recordingVerifier{calls: &calls}

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	if got := strings.Join(calls, ","); got != "verify,ensure" {
		t.Fatalf("calls = %q, want the image verified before it is pulled", got)
	}
	if len(rt.ensuredImages) != 1 || rt.ensuredImages[0] != DefaultImage {
		t.Errorf("pulled %v, want the pinned default %q", rt.ensuredImages, DefaultImage)
	}
}

func TestStartSessionRefusesAnUnverifiedImage(t *testing.T) {
	var calls []string
	rt := pullRecordingRuntime{fakeRuntime: newFakeRuntime(), calls: &calls}
	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.Verifier = recordingVerifier{calls: &calls, err: errors.New("signature does not verify")}

	if _, err := StartSession(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("StartSession(unverified) = %v, want the verifier's refusal", err)
	}
	if len(rt.ensuredImages) != 0 {
		t.Errorf("pulled %v after verification failed, want no pull", rt.ensuredImages)
	}
	if rt.networks != nil && len(rt.networks) != 0 {
		t.Errorf("created %d networks before verification passed, want none", len(rt.networks))
	}
}

// TestSessionReadsTheToolsetOnce covers discovery (§9): one read after start,
// exposed to the caller, and never a probe.
func TestSessionReadsTheToolsetOnce(t *testing.T) {
	rt := newFakeRuntime()
	rt.execResult = ExecResult{Stdout: sandbox.ToolsetManifest}
	opts := enforcedOptions(rt, &fakeFirewall{})

	var checked []byte
	opts.CheckToolset = func(manifest []byte) error {
		checked = manifest
		return nil
	}

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession() = %v", err)
	}
	defer func() { _ = s.Close() }()

	if len(rt.execs) != 1 || len(rt.execs[0].Cmd) != 2 || rt.execs[0].Cmd[0] != "cat" {
		t.Fatalf("execs = %+v, want exactly one cat of the declaration", rt.execs)
	}
	if !strings.Contains(string(checked), `"schema_version":1`) {
		t.Errorf("CheckToolset got %q, want the image's manifest", checked)
	}
	if got := s.Toolset(); string(got) != sandbox.ToolsetManifest {
		t.Errorf("Toolset() = %q, want the declared manifest", got)
	}
}

// TestSessionRefusesAToolsetThatContradictsTheBinary covers §6.3: an image
// built out of step with this binary would make the prompt lie.
func TestSessionRefusesAToolsetThatContradictsTheBinary(t *testing.T) {
	rt := newFakeRuntime()
	rt.execResult = ExecResult{Stdout: sandbox.ToolsetManifest}
	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.CheckToolset = func([]byte) error { return errors.New("toolset mismatch") }

	_, err := StartSession(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "toolset mismatch") {
		t.Fatalf("StartSession(mismatched toolset) = %v, want a refusal", err)
	}
	if len(rt.removedContainers) != 1 {
		t.Errorf("removed containers = %v, want the refused session torn down", rt.removedContainers)
	}
}

// TestSessionToleratesAnImageWithNoManifest: absent is "toolset unknown", not
// a failure — the session still runs (§9).
func TestSessionToleratesAnImageWithNoManifest(t *testing.T) {
	rt := newFakeRuntime()
	rt.execResult = ExecResult{Stdout: "", ExitCode: 1}
	opts := enforcedOptions(rt, &fakeFirewall{})
	opts.CheckToolset = func([]byte) error { return errors.New("must not be called") }

	s, err := StartSession(context.Background(), opts)
	if err != nil {
		t.Fatalf("StartSession(no manifest) = %v", err)
	}
	defer func() { _ = s.Close() }()
	if s.Toolset() != nil {
		t.Errorf("Toolset() = %q, want unknown", s.Toolset())
	}
}
