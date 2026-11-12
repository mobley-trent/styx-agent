package sandbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The compiled-in signing policy (docs/sandbox-image.md §6.1). Both strings are
// part of styx's trust contract: renaming the workflow is a breaking change
// discovered by a failing verification, never a silent trust widening.
const (
	// Issuer is the OIDC issuer the signing certificate must name.
	Issuer = "https://token.actions.githubusercontent.com"
	// Identity is the sandbox workflow on main that must have signed.
	Identity = "https://github.com/mobley-trent/styx-agent/.github/workflows/sandbox-image.yml@refs/heads/main"
)

// Error is a verification failure. It names the digest, what stage failed, and
// the policy that was applied, so the refusal an operator sees is actionable
// rather than a bare "verification failed" (§6.3).
type Error struct {
	// Ref is the image that did not verify.
	Ref Ref
	// Stage is where it failed: reference, fetch, bundle, signature, or claim.
	Stage string
	// Reason is the underlying cause, verbatim.
	Reason string
}

// Error implements error.
func (e *Error) Error() string {
	image := e.Ref.String()
	if e.Ref.Digest == "" {
		image = e.Ref.Repository
	}
	return fmt.Sprintf("sandbox image %s did not verify (%s): %s (expected certificate identity %s issued by %s)",
		image, e.Stage, e.Reason, Identity, Issuer)
}

// Verifier verifies a digest-pinned image's signature against the embedded
// root and policy, caching a verified bundle so later starts — and air-gapped
// hosts — verify offline (docs/sandbox-image.md §6).
type Verifier struct {
	source   BundleSource
	cache    Cache
	material root.TrustedMaterial
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithSource replaces the signature source (tests).
func WithSource(source BundleSource) Option {
	return func(v *Verifier) { v.source = source }
}

// WithCacheDir replaces the trust cache directory (tests).
func WithCacheDir(dir string) Option {
	return func(v *Verifier) { v.cache.Dir = dir }
}

// NewVerifier builds a verifier over the embedded trusted root and policy.
func NewVerifier(opts ...Option) (*Verifier, error) {
	v := &Verifier{source: &Registry{}}
	for _, opt := range opts {
		opt(v)
	}
	if v.source == nil {
		return nil, errors.New("sandbox: a verifier needs a signature source")
	}
	if v.cache.Dir == "" {
		dir, err := DefaultCacheDir()
		if err != nil {
			return nil, err
		}
		v.cache.Dir = dir
	}
	material, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("sandbox: embedded trusted root: %w", err)
	}
	v.material = material
	return v, nil
}

// VerifyImage verifies a reference in its registry spelling. It is the seam
// containerlayer calls before an image is pulled.
func (v *Verifier) VerifyImage(ctx context.Context, ref string) error {
	parsed, err := ParseRef(ref)
	if err != nil {
		return &Error{Ref: Ref{Repository: ref}, Stage: "reference", Reason: err.Error()}
	}
	return v.Verify(ctx, parsed)
}

// Verify checks the signature over ref, offline when a verified bundle is
// already cached.
func (v *Verifier) Verify(ctx context.Context, ref Ref) error {
	artifact, cached := v.cache.load(ref)
	if !cached {
		fetched, err := v.source.Signature(ctx, ref)
		if err != nil {
			return &Error{Ref: ref, Stage: "fetch", Reason: err.Error()}
		}
		artifact = fetched
	}
	if err := v.check(ref, artifact); err != nil {
		return err
	}
	if cached {
		return nil
	}

	// A successful verification caches the bundle, and the toolset the pin
	// embeds, for the air-gap path (§6.2). The cache records nothing about a
	// run in which verification failed.
	toolset, err := EmbeddedToolset()
	if err != nil {
		return &Error{Ref: ref, Stage: "bundle", Reason: err.Error()}
	}
	canonical, err := toolset.Canonical()
	if err != nil {
		return &Error{Ref: ref, Stage: "bundle", Reason: err.Error()}
	}
	if err := v.cache.store(ref, artifact, canonical); err != nil {
		return &Error{Ref: ref, Stage: "cache", Reason: err.Error()}
	}
	return nil
}

// check verifies one artifact against the policy: the certificate chains to the
// embedded Fulcio root, its SCT and the Rekor entry's signed timestamp verify,
// the identity and issuer match, the signature covers the payload, and the
// payload claims this exact digest.
func (v *Verifier) check(ref Ref, artifact SignatureArtifact) error {
	pb, digest, err := protobundleFor(artifact)
	if err != nil {
		return &Error{Ref: ref, Stage: "bundle", Reason: err.Error()}
	}
	entity, err := bundle.NewProtobufBundle(pb)
	if err != nil {
		return &Error{Ref: ref, Stage: "bundle", Reason: err.Error()}
	}
	identity, err := verify.NewShortCertificateIdentity(Issuer, "", Identity, "")
	if err != nil {
		return &Error{Ref: ref, Stage: "signature", Reason: err.Error()}
	}
	// The policy, in the order sigstore applies it: the Rekor entry must be
	// verified (the legacy artifact carries an inclusion promise, so the
	// signed entry timestamp is what proves the log accepted it), its
	// integrated timestamp must fall inside the certificate's validity, and
	// the Fulcio certificate's SCT must chain to a CT log we trust.
	verifier, err := verify.NewVerifier(v.material,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	if err != nil {
		return &Error{Ref: ref, Stage: "signature", Reason: err.Error()}
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(identity),
	)
	if _, err := verifier.Verify(entity, policy); err != nil {
		return &Error{Ref: ref, Stage: "signature", Reason: err.Error()}
	}
	if err := verifyClaim(artifact.Payload, ref); err != nil {
		return &Error{Ref: ref, Stage: "claim", Reason: err.Error()}
	}
	return nil
}
