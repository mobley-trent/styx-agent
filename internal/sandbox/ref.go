package sandbox

import (
	"fmt"
	"regexp"
	"strings"
)

// digestPattern is the only image identity the harness accepts: a sha256
// digest. A tag is a human convenience the harness never resolves
// (docs/sandbox-image.md §1, §5).
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Ref is an image reference pinned by digest — `repository@sha256:<64 hex>`.
type Ref struct {
	// Repository is the image's registry path, without a tag or digest, e.g.
	// `ghcr.io/mobley-trent/styx-sandbox`.
	Repository string
	// Digest is the manifest-list index digest, e.g. `sha256:4ecf…`.
	Digest string
}

// ParseRef parses a digest-pinned reference. Anything not pinned by digest is
// refused: the harness has no code path that resolves a tag
// (docs/sandbox-image.md §7).
func ParseRef(ref string) (Ref, error) {
	s := strings.TrimSpace(ref)
	repository, digest, ok := strings.Cut(s, "@")
	repository = strings.TrimSpace(repository)
	if !ok || repository == "" || strings.TrimSpace(digest) == "" {
		return Ref{}, fmt.Errorf("image %q is not pinned by digest (want <repository>@sha256:…)", s)
	}
	if !digestPattern.MatchString(digest) {
		return Ref{}, fmt.Errorf("image %q has no valid sha256 digest", s)
	}
	if strings.ContainsAny(repository, " \t") {
		return Ref{}, fmt.Errorf("image %q has a malformed repository", s)
	}
	return Ref{Repository: repository, Digest: digest}, nil
}

// MustParseRef is ParseRef for compile-time-known references (the generated
// pin). It panics on a malformed pin, which scripts/sandbox-bump.sh cannot
// produce and a hand edit must not ship.
func MustParseRef(ref string) Ref {
	r, err := ParseRef(ref)
	if err != nil {
		panic("sandbox: " + err.Error())
	}
	return r
}

// String renders the reference as the registry spells it.
func (r Ref) String() string { return r.Repository + "@" + r.Digest }

// Hex is the digest without its algorithm prefix, which is how the cosign
// artifact's tag names it: `sha256-<hex>.sig`.
func (r Ref) Hex() string { return strings.TrimPrefix(r.Digest, "sha256:") }

// Host splits the repository into its registry host and repository path,
// defaulting to Docker Hub for a bare `owner/name`.
func (r Ref) Host() (host, path string) {
	first, rest, ok := strings.Cut(r.Repository, "/")
	if !ok {
		return "docker.io", "library/" + r.Repository
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first, rest
	}
	return "docker.io", r.Repository
}

// Official reports whether the reference is the compiled-in pinned image.
func (r Ref) Official() bool { return r.String() == ImageRef }
