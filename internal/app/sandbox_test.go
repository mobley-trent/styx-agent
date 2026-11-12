package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sandbox"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// customRef is a digest-pinned image that is not the official one: the shape a
// private mirror or a local development build arrives in.
const customRef = "ghcr.io/example/lab@sha256:" +
	"1111111111111111111111111111111111111111111111111111111111111111"

// refusingVerifier fails every image, standing in for a failed signature.
type refusingVerifier struct{ err error }

func (r refusingVerifier) VerifyImage(context.Context, string) error { return r.err }

// buildForImage builds a harness whose config pins image, without starting
// anything.
func buildForImage(t *testing.T, image string, opts ...func(*Options)) (*Harness, error) {
	t.Helper()
	dir := t.TempDir()
	if image != "" {
		writeFile(t, dir, ".styx/config.yaml", "container:\n  image: "+image+"\n")
	}
	options := buildOptions(t, dir, fakemodel.New())
	for _, opt := range opts {
		opt(&options)
	}
	return Build(context.Background(), options)
}

func TestOfficialImageNeedsNoFlag(t *testing.T) {
	h, err := buildForImage(t, "")
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	image, official, err := h.sessionImage()
	if err != nil {
		t.Fatalf("sessionImage() = %v", err)
	}
	if !official || image != sandbox.ImageRef {
		t.Fatalf("sessionImage() = %q, official %v; want the pinned reference", image, official)
	}
	// The prompt describes the pinned toolset, so the model knows what it can
	// run before the container exists.
	if h.Prompt == "" || !strings.Contains(h.Prompt, "nmap") || !strings.Contains(h.Prompt, "nmap_parse") {
		t.Fatalf("the prompt does not carry the pinned toolset:\n%s", h.Prompt)
	}
}

func TestTagPinnedImageIsAUsageError(t *testing.T) {
	_, err := buildForImage(t, "ghcr.io/example/lab:latest")
	var usage UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("Build(tag image) = %v, want a usage refusal", err)
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("refusal does not say why: %v", err)
	}
}

func TestCustomImageWithoutTheFlagRefuses(t *testing.T) {
	_, err := buildForImage(t, customRef)
	var usage UsageError
	if !errors.As(err, &usage) || !strings.Contains(err.Error(), "--allow-unverified-image") {
		t.Fatalf("Build(custom image, no flag) = %v, want a usage refusal naming the flag", err)
	}
}

func TestCustomImageWithTheFlagIsDescribedAsUnknown(t *testing.T) {
	h, err := buildForImage(t, customRef, func(o *Options) { o.AllowUnverifiedImage = true })
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	image, official, err := h.sessionImage()
	if err != nil {
		t.Fatalf("sessionImage() = %v", err)
	}
	if official || image != customRef {
		t.Fatalf("sessionImage() = %q, official %v; want the custom reference", image, official)
	}
	if !strings.Contains(h.Prompt, "operator-pinned") {
		t.Fatalf("the prompt claims to know a toolset it cannot know:\n%s", h.Prompt)
	}
	if strings.Contains(h.Prompt, "nmap_parse") {
		t.Fatalf("the prompt lists an operator image's tools:\n%s", h.Prompt)
	}
}

// TestUnverifiedImageNeedsTheOperatorsYes is the door itself: a waived image
// runs only on an explicit yes, never on silence.
func TestUnverifiedImageNeedsTheOperatorsYes(t *testing.T) {
	h, err := buildForImage(t, customRef, func(o *Options) { o.AllowUnverifiedImage = true })
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	verifier := h.imageVerifier(customRef, false)
	if err := verifier.VerifyImage(context.Background(), customRef); err == nil {
		t.Fatal("an unverified image ran with no operator attached, want a refusal")
	}

	var asked tui.Prompt
	h.setPromptUI(func(msg tui.PromptMsg) {
		asked = msg.Prompt
		msg.Reply(tui.ChoiceAllowOnce)
	})
	if err := verifier.VerifyImage(context.Background(), customRef); err != nil {
		t.Fatalf("VerifyImage(operator approved) = %v", err)
	}
	if asked.Kind != tui.PromptUnverified || asked.Tool != customRef {
		t.Fatalf("prompt = %+v, want the unverified-image card naming the image", asked)
	}
}

// TestVerifiedImageIsAudited covers the session-start record: the pull is
// harness plumbing, so the decision lives in the audit trail even though it is
// not a tool call (docs/sandbox-image.md §10).
func TestVerifiedImageIsAudited(t *testing.T) {
	h, err := buildForImage(t, "", func(o *Options) {
		o.SandboxVerifier = refusingVerifier{err: errors.New("signature does not verify")}
	})
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	err = h.imageVerifier(sandbox.ImageRef, true).VerifyImage(context.Background(), sandbox.ImageRef)
	if err == nil || !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("VerifyImage(failing verifier) = %v, want the verifier's error", err)
	}
	trail := readAudit(t, h)
	if !strings.Contains(trail, `"tool":"sandbox_image"`) || !strings.Contains(trail, `"verdict":"deny"`) {
		t.Fatalf("audit trail has no image decision: %s", trail)
	}
}

func TestToolsetMismatchRefusesTheSession(t *testing.T) {
	check := officialToolsetCheck(true)
	if err := check([]byte(sandbox.ToolsetManifest)); err != nil {
		t.Fatalf("check(pinned manifest) = %v", err)
	}
	other := strings.Replace(sandbox.ToolsetManifest, `"image_version":"`+sandbox.Version+`"`, `"image_version":"sandbox-v1.2026.10.1"`, 1)
	if err := check([]byte(other)); err == nil {
		t.Fatal("a toolset from another build passed the check, want a refusal")
	}
	if check := officialToolsetCheck(false); check != nil {
		t.Fatal("an operator image should not be checked against the embedded toolset")
	}
}

// TestToolsetDigestDeliversOnce covers an operator image's declaration reaching
// the model as turn content, and only once.
func TestToolsetDigestDeliversOnce(t *testing.T) {
	container := containerlayer.NewManager(containerlayer.ManagerOptions{
		RuntimeFactory: func() (containerlayer.Runtime, error) { return &appFakeRuntime{}, nil },
		Firewall:       appFakeFirewall{},
		Image:          customRef,
	})
	digest := &toolsetDigest{container: container}

	if body, ok := digest.Digest(false); ok || body != "" {
		t.Fatalf("Digest(before the container starts) = %q, %v; want nothing yet", body, ok)
	}
	if _, err := container.Start(context.Background()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	defer func() { _ = container.Close() }()

	body, ok := digest.Digest(false)
	if !ok || !strings.Contains(body, "nmap") || !strings.Contains(body, "nmap_parse") {
		t.Fatalf("Digest(after start) = %q, %v; want the toolset", body, ok)
	}
	if _, ok := digest.Digest(false); ok {
		t.Fatal("the toolset was delivered twice")
	}
}

// readAudit returns the session audit file's contents.
func readAudit(t *testing.T, h *Harness) string {
	t.Helper()
	h.mu.Lock()
	path := ""
	if h.audit != nil {
		path = h.audit.Path()
	}
	h.mu.Unlock()
	if path == "" {
		t.Fatal("harness has no audit trail")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit trail: %v", err)
	}
	return string(data)
}
