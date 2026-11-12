package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/mobley-trent/styx-agent/internal/agent"
	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/containerlayer"
	"github.com/mobley-trent/styx-agent/internal/sandbox"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// This file is the harness's half of the sandbox image decision
// (docs/sandbox-image.md): which image a session runs, whether its signature is
// verified, what the model is told about its toolset, and how all of that
// reaches the audit trail. The container layer only sees an ImageVerifier; the
// signature mechanism itself lives in internal/sandbox.

// UsageError is a startup refusal the CLI reports as a usage error (exit 2):
// the run was configured in a way the harness will not act on, rather than
// failing while doing what it was asked.
type UsageError struct{ Message string }

// Error implements error.
func (e UsageError) Error() string { return e.Message }

// IsUsageError reports whether err is a usage refusal.
func IsUsageError(err error) bool {
	var usage UsageError
	return errors.As(err, &usage)
}

// sessionImage resolves the image a session runs: the configured one, or the
// pinned default, and whether it is the image whose trust is compiled in. A
// reference that is not pinned by digest is always a refusal — a tag is a name
// the harness never resolves — and a pinned image that is not the official
// digest runs only through the explicit, audited waiver (docs/sandbox-image.md
// §5, §7).
func (h *Harness) sessionImage() (image string, official bool, err error) {
	ref := strings.TrimSpace(h.Config.Container.Image)
	if ref == "" {
		return sandbox.ImageRef, true, nil
	}
	parsed, parseErr := sandbox.ParseRef(ref)
	if parseErr != nil {
		return "", false, UsageError{Message: fmt.Sprintf("refusing to start: %v (docs/sandbox-image.md §7)", parseErr)}
	}
	if parsed.Digest == sandbox.Digest {
		// A mirror of the pinned bytes is the pinned image: trust flows from
		// the digest, not from the repository it is fetched from.
		return parsed.String(), true, nil
	}
	if !h.allowUnverifiedImage {
		return "", false, UsageError{Message: fmt.Sprintf(
			"refusing to start: %s is not the pinned sandbox image %s; pass --allow-unverified-image to run it unverified (docs/sandbox-image.md §7)",
			parsed, sandbox.ImageRef)}
	}
	return parsed.String(), false, nil
}

// imageVerifier builds the verification the session start runs before anything
// is pulled. The official digest is verified against the embedded root and
// policy; any other image is the explicit waiver door, which asks the operator
// once and records the decision.
func (h *Harness) imageVerifier(image string, official bool) containerlayer.ImageVerifier {
	if !official {
		return &auditVerifier{h: h, image: image, unverified: true}
	}
	next := h.sandboxVerifier
	if next == nil {
		verifier, err := sandbox.NewVerifier()
		if err != nil {
			next = failingVerifier{err: err}
		} else {
			next = verifier
		}
	}
	return &auditVerifier{h: h, image: image, next: next}
}

// failingVerifier refuses every image: a verifier that cannot be constructed
// (an unreadable embedded root) must not degrade into "trust everything".
type failingVerifier struct{ err error }

// VerifyImage implements containerlayer.ImageVerifier.
func (f failingVerifier) VerifyImage(context.Context, string) error { return f.err }

// auditVerifier is the session-start image decision: it records the result in
// the audit trail, because the pull is harness-side plumbing rather than a tool
// call (docs/sandbox-image.md §10), and it is the one place the unverified door
// asks the operator (§7).
type auditVerifier struct {
	h          *Harness
	image      string
	next       containerlayer.ImageVerifier
	unverified bool
}

// VerifyImage implements containerlayer.ImageVerifier.
func (a *auditVerifier) VerifyImage(ctx context.Context, ref string) error {
	if a.unverified {
		choice, err := a.h.askOperator(ctx, tui.Prompt{
			Kind:   tui.PromptUnverified,
			Tool:   a.image,
			Path:   digestOf(ref),
			Reason: "signature waived",
		})
		if err != nil {
			return err
		}
		if choice != tui.ChoiceAllowOnce {
			// No operator attached (a headless run), or the operator said no:
			// an unverified image never runs on silence.
			return fmt.Errorf("refusing to run unverified image %s: verification was waived, but no operator approved it at startup (docs/sandbox-image.md §7)", ref)
		}
		return a.record(ref, audit.VerdictAllowOnce, "unverified-image-waived")
	}
	if err := a.next.VerifyImage(ctx, ref); err != nil {
		// The denial is part of the trail too, so an operator later asking
		// "why did it not start" finds the answer in the audit.
		_ = a.record(ref, audit.VerdictDeny, "verification-failed")
		return err
	}
	return a.record(ref, audit.VerdictAllow, "verified")
}

// record appends the session-start image decision. A failed write refuses the
// session (fail closed): the audit trail is the forensic record of what was
// run, and the image is the largest thing a session runs.
func (a *auditVerifier) record(ref string, verdict audit.Verdict, reason string) error {
	if a.h.audit == nil {
		return nil
	}
	return a.h.audit.Append(audit.Record{
		Mode: audit.Mode(a.h.Mode),
		Tool: "sandbox_image",
		Params: map[string]any{
			"image":      ref,
			"digest":     digestOf(ref),
			"unverified": a.unverified,
		},
		Verdict: verdict,
		Reason:  reason,
	})
}

// digestOf extracts the digest from a reference for the record, empty when the
// reference carries none.
func digestOf(ref string) string {
	if _, digest, ok := strings.Cut(ref, "@"); ok {
		return digest
	}
	return ""
}

// promptToolset is the prompt's view of the session image (docs/sandbox-image.md
// §9): the pinned image's declaration is compiled in and rides the byte-stable
// prefix; an operator-pinned image cannot be described until its container
// starts, so the prompt says exactly that instead of guessing.
func (h *Harness) promptToolset(official bool) *agent.SandboxToolset {
	if !official {
		return &agent.SandboxToolset{Unknown: true}
	}
	toolset, err := sandbox.EmbeddedToolset()
	if err != nil {
		return &agent.SandboxToolset{Unknown: true}
	}
	out := &agent.SandboxToolset{Image: sandbox.ImageRef, ImageVersion: toolset.ImageVersion}
	for _, tool := range toolset.Tools {
		entry := agent.SandboxTool{Name: tool.Name, Version: tool.Version}
		if tool.Parser != nil {
			entry.Parser = *tool.Parser
		}
		out.Tools = append(out.Tools, entry)
	}
	return out
}

// officialToolsetCheck refuses a session whose image declares a toolset that
// disagrees with the one compiled into this binary: the binary and the image
// were built out of step, and the prompt would describe tools that are not
// there (docs/sandbox-image.md §6.3).
func officialToolsetCheck(official bool) func([]byte) error {
	if !official {
		return nil
	}
	embedded, err := sandbox.EmbeddedToolset()
	if err != nil {
		return func([]byte) error { return err }
	}
	return func(manifest []byte) error { return sandbox.SameToolset(embedded, manifest) }
}

// toolsetDigest delivers an operator-pinned image's toolset to the model as
// ordinary turn content (docs/sandbox-image.md §9, docs/spec.md §4.5). It is a
// digest rather than a prompt section precisely because it is not knowable
// before the container starts, and the byte-stable prefix is never amended
// mid-session.
type toolsetDigest struct {
	container *containerlayer.Manager

	mu        sync.Mutex
	delivered bool
}

// Digest implements agent.StateDigest.
func (d *toolsetDigest) Digest(bool) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.delivered || d.container == nil {
		return "", false
	}
	manifest := d.container.Info().Toolset
	if len(manifest) == 0 {
		return "", false
	}
	d.delivered = true
	description, err := sandbox.Describe(manifest)
	if err != nil {
		// The declaration is present but unreadable: say that, which is true,
		// rather than present a half-parsed toolset as fact.
		return "sandbox toolset: the image declares a manifest this harness cannot read; treat the toolset as unknown", true
	}
	return description, true
}

// sandboxDigests merges the turn-content sources the loop takes through one
// seam: the engagement state digest and, for an operator-pinned image, the
// toolset it declares. Both are ordinary turn content, and the loop owns where
// it goes (docs/engagement-state.md §8).
type sandboxDigests []agent.StateDigest

// Digest implements agent.StateDigest.
func (c sandboxDigests) Digest(force bool) (string, bool) {
	var parts []string
	for _, d := range c {
		if body, ok := d.Digest(force); ok && body != "" {
			parts = append(parts, body)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "\n\n"), true
}
