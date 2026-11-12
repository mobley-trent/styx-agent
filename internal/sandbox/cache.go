package sandbox

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// trustedRootJSON is Sigstore's public-good trusted root (Fulcio certificate
// authorities, CT log keys, and the Rekor log's key), vendored so verification
// needs no TUF, Fulcio, or Rekor request at verification time
// (docs/sandbox-image.md §6.1). It is a build-time input, not a runtime fetch:
// a rotation of the root is a styx release.
//
// Source: sigstore-go's public-good test fixture, which is the published trust
// root (media type application/vnd.dev.sigstore.trustedroot+json;version=0.1).
//
//go:embed trustedroot.json
var trustedRootJSON []byte

// DefaultCacheDir is the XDG trust cache root: `$XDG_DATA_HOME/styx/sandbox`.
func DefaultCacheDir() (string, error) {
	if base := os.Getenv("XDG_DATA_HOME"); base != "" {
		return filepath.Join(base, "styx", "sandbox"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("sandbox: trust cache: %w", err)
	}
	return filepath.Join(home, ".local", "share", "styx", "sandbox"), nil
}

// Cache is the on-disk trust cache: one directory per verified index digest,
// holding the verified bundle and the toolset it describes (§6.2). A
// pre-pulled image without a cached bundle is unverified, not trusted by
// existence: nothing here is consulted for an image that was never verified.
type Cache struct {
	// Dir is the cache root.
	Dir string
}

// dirFor is the cache directory for one digest.
func (c Cache) dirFor(ref Ref) string { return filepath.Join(c.Dir, ref.Hex()) }

// load reads the cached bundle for a digest. A missing cache is not an error —
// it means the image must be verified online.
func (c Cache) load(ref Ref) (SignatureArtifact, bool) {
	if c.Dir == "" {
		return SignatureArtifact{}, false
	}
	data, err := os.ReadFile(filepath.Join(c.dirFor(ref), "bundle.json"))
	if err != nil {
		return SignatureArtifact{}, false
	}
	artifact, err := decodeArtifact(data)
	if err != nil {
		return SignatureArtifact{}, false
	}
	return artifact, true
}

// store writes the verified bundle and the toolset beside it, atomically: a
// half-written cache entry would be read as a corrupt bundle next start.
func (c Cache) store(ref Ref, artifact SignatureArtifact, toolset []byte) error {
	dir := c.dirFor(ref)
	//nolint:gosec // the cache path is derived from a digest, not user input.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	bundle, err := encodeArtifact(artifact)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "bundle.json"), bundle); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "toolset.json"), toolset)
}

// writeFileAtomic writes data to path through a temporary file and a rename, so
// a reader sees either the old content or the new, never a partial write.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	//nolint:gosec // the cache path is derived from a digest, not user input.
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

// TrustedRoot returns the embedded root's JSON, for tests that assert the
// vendored copy is the one being verified against.
func TrustedRoot() []byte { return trustedRootJSON }
