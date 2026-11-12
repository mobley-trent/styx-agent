package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// fixtureArtifact builds the real published signature artifact from the fixtures
// captured with sandbox-v1.2026.11.11: the OCI manifest's cosign annotations and
// the simple-signing payload blob they cover.
func fixtureArtifact(t *testing.T) SignatureArtifact {
	t.Helper()
	manifestData, err := os.ReadFile(filepath.Join("testdata", "signature-manifest.json"))
	if err != nil {
		t.Fatalf("read signature manifest fixture: %v", err)
	}
	payload, err := os.ReadFile(filepath.Join("testdata", "signature-payload.json"))
	if err != nil {
		t.Fatalf("read signature payload fixture: %v", err)
	}
	var m struct {
		Layers []ociLayer `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &m); err != nil {
		t.Fatalf("parse signature manifest fixture: %v", err)
	}
	if len(m.Layers) != 1 {
		t.Fatalf("fixture has %d layers, want 1", len(m.Layers))
	}
	artifact, err := artifactFromAnnotations(m.Layers[0].Annotations, payload)
	if err != nil {
		t.Fatalf("flatten signature artifact: %v", err)
	}
	return artifact
}

func TestParseRef(t *testing.T) {
	good := "ghcr.io/mobley-trent/styx-sandbox@sha256:4ecf7a3a70082cf5b6d1b377532e39708d53e45edb5eff37d8cfff3db8d66fad"
	ref, err := ParseRef(good)
	if err != nil {
		t.Fatalf("ParseRef(%q) = %v", good, err)
	}
	if ref.String() != good {
		t.Errorf("Ref.String() = %q, want round trip to %q", ref.String(), good)
	}
	host, path := ref.Host()
	if host != "ghcr.io" || path != "mobley-trent/styx-sandbox" {
		t.Errorf("Host() = %q, %q", host, path)
	}

	for _, bad := range []string{
		"",
		"ghcr.io/mobley-trent/styx-sandbox:latest",
		"ghcr.io/mobley-trent/styx-sandbox@sha256:abc",
		"@sha256:4ecf7a3a70082cf5b6d1b377532e39708d53e45edb5eff37d8cfff3db8d66fad",
		"ghcr.io/mobley-trent/styx-sandbox@md5:4ecf7a3a70082cf5b6d1b377532e39708d53e45edb5eff37d8cfff3db8d66fad",
	} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) = nil error, want a digest-pinning refusal", bad)
		}
	}
}

func TestOfficialToolsetMatchesThePublishedManifest(t *testing.T) {
	embedded, err := EmbeddedToolset()
	if err != nil {
		t.Fatalf("embedded toolset: %v", err)
	}
	published, err := os.ReadFile(filepath.Join("testdata", "toolset-2026.11.11.json"))
	if err != nil {
		t.Fatalf("read published toolset fixture: %v", err)
	}
	if err := SameToolset(embedded, published); err != nil {
		t.Fatalf("embedded toolset disagrees with the published manifest: %v", err)
	}
	if embedded.ImageVersion != Version {
		t.Errorf("embedded toolset is %s, pin says %s", embedded.ImageVersion, Version)
	}
}

func TestParseToolsetRejectsWhatItCannotDescribe(t *testing.T) {
	valid := `{"schema_version":1,"image_version":"sandbox-v1.2026.11.0","base":"docker.io/x@sha256:` + strings.Repeat("a", 64) + `",` +
		`"tools":[{"name":"nmap","version":"7.99","parser":"nmap_parse"}],` +
		`"wordlists":[{"name":"w","path":"/usr/share/wordlists/styx/w.txt","sha256":"` + strings.Repeat("b", 64) + `"}],` +
		`"data":{"nuclei_templates":"v1","semgrep_rules":"v1","trivy_db":"sha256:` + strings.Repeat("c", 64) + `",` +
		`"trivy_java_db":"sha256:` + strings.Repeat("d", 64) + `","seclists":"` + strings.Repeat("e", 40) + `"}}`

	if _, err := ParseToolset([]byte(valid)); err != nil {
		t.Fatalf("ParseToolset(valid) = %v", err)
	}

	cases := map[string]string{
		"unknown field":    strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"extra":true`, 1),
		"schema version":   strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		"empty tools":      strings.Replace(valid, `"tools":[{"name":"nmap","version":"7.99","parser":"nmap_parse"}]`, `"tools":[]`, 1),
		"unknown parser":   strings.Replace(valid, `"parser":"nmap_parse"`, `"parser":"made_up_parse"`, 1),
		"missing data":     strings.Replace(valid, `"nuclei_templates":"v1"`, `"nuclei_templates":""`, 1),
		"unpinned base":    strings.Replace(valid, `@sha256:`+strings.Repeat("a", 64), `:latest`, 1),
		"not json":         `{`,
		"trailing garbage": valid + `{}`,
	}
	for name, body := range cases {
		if _, err := ParseToolset([]byte(body)); err == nil {
			t.Errorf("ParseToolset(%s) = nil error, want a refusal", name)
		}
	}
}

// TestVerifyPublishedArtifact is the end-to-end check against the real bytes:
// the published signature for the pinned digest verifies against the embedded
// trusted root and policy, offline.
func TestVerifyPublishedArtifact(t *testing.T) {
	v, err := NewVerifier(WithCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ref := MustParseRef(ImageRef)
	if err := v.check(ref, fixtureArtifact(t)); err != nil {
		t.Fatalf("the published signature did not verify: %v", err)
	}
}

// TestVerifyRejectsAnotherIdentity proves the policy is the identity, not just
// a valid signature: the same bundle verifies for our workflow and fails for any
// other.
func TestVerifyRejectsAnotherIdentity(t *testing.T) {
	artifact := fixtureArtifact(t)
	v, err := NewVerifier(WithCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	pb, digest, err := protobundleFor(artifact)
	if err != nil {
		t.Fatalf("protobundleFor: %v", err)
	}
	entity, err := bundle.NewProtobufBundle(pb)
	if err != nil {
		t.Fatalf("NewProtobufBundle: %v", err)
	}
	other, err := verify.NewShortCertificateIdentity(Issuer, "", "https://github.com/someone-else/repo/.github/workflows/sandbox-image.yml@refs/heads/main", "")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	verifier, err := verify.NewVerifier(v.material,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(other))
	if _, err := verifier.Verify(entity, policy); err == nil {
		t.Fatal("a bundle signed for another identity verified, want a refusal")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	v, err := NewVerifier(WithCacheDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ref := MustParseRef(ImageRef)

	tampered := fixtureArtifact(t)
	tampered.Signature[0] ^= 0xff
	err = v.check(ref, tampered)
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Stage != "signature" {
		t.Fatalf("check(tampered signature) = %v, want a signature-stage refusal", err)
	}

	rewritten := fixtureArtifact(t)
	rewritten.Payload = []byte(`{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"sha256:` + strings.Repeat("c", 64) + `"}}}`)
	err = v.check(ref, rewritten)
	if !errors.As(err, &refusal) || refusal.Stage != "signature" {
		t.Fatalf("check(rewritten payload) = %v, want a signature-stage refusal", err)
	}
}

func TestClaimMustNameThePinnedDigest(t *testing.T) {
	ref := MustParseRef(ImageRef)
	if err := verifyClaim([]byte(`{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"`+ref.Digest+`"}}}`), ref); err != nil {
		t.Fatalf("verifyClaim(pinned digest) = %v", err)
	}
	other := MustParseRef("ghcr.io/mobley-trent/styx-sandbox@sha256:" + strings.Repeat("d", 64))
	err := verifyClaim([]byte(`{"critical":{"type":"cosign container image signature","image":{"docker-manifest-digest":"`+ref.Digest+`"}}}`), other)
	if err == nil || !strings.Contains(err.Error(), "not the pinned") {
		t.Fatalf("verifyClaim(foreign digest) = %v, want a claim mismatch", err)
	}
}

// fakeSource stands in for the registry: one artifact, or a failure.
type fakeSource struct {
	artifact SignatureArtifact
	err      error
	calls    int
}

func (f *fakeSource) Signature(context.Context, Ref) (SignatureArtifact, error) {
	f.calls++
	if f.err != nil {
		return SignatureArtifact{}, f.err
	}
	return f.artifact, nil
}

func TestVerifyCachesAndThenWorksOffline(t *testing.T) {
	cacheDir := t.TempDir()
	ref := MustParseRef(ImageRef)
	source := &fakeSource{artifact: fixtureArtifact(t)}

	v, err := NewVerifier(WithCacheDir(cacheDir), WithSource(source))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), ref); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, name := range []string{"bundle.json", "toolset.json"} {
		if _, err := os.Stat(filepath.Join(cacheDir, ref.Hex(), name)); err != nil {
			t.Errorf("cache is missing %s: %v", name, err)
		}
	}

	// A second start with no registry at all still verifies: the cached bundle
	// is re-verified against the embedded root, not trusted by existence.
	offline := &fakeSource{err: errors.New("registry unreachable")}
	v2, err := NewVerifier(WithCacheDir(cacheDir), WithSource(offline))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v2.Verify(context.Background(), ref); err != nil {
		t.Fatalf("offline Verify: %v", err)
	}
	if offline.calls != 0 {
		t.Errorf("offline verification consulted the registry %d times", offline.calls)
	}
}

func TestVerifyWithoutCacheAndRegistryFails(t *testing.T) {
	v, err := NewVerifier(WithCacheDir(t.TempDir()), WithSource(&fakeSource{err: errors.New("registry unreachable")}))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	err = v.Verify(context.Background(), MustParseRef(ImageRef))
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Stage != "fetch" {
		t.Fatalf("Verify(no cache, no registry) = %v, want a fetch-stage refusal", err)
	}
	if !strings.Contains(err.Error(), "expected certificate identity "+Identity) {
		t.Errorf("refusal does not name the expected identity: %v", err)
	}
}

func TestVerifyImageRejectsATag(t *testing.T) {
	v, err := NewVerifier(WithCacheDir(t.TempDir()), WithSource(&fakeSource{}))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	err = v.VerifyImage(context.Background(), "ghcr.io/mobley-trent/styx-sandbox:latest")
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Stage != "reference" {
		t.Fatalf("VerifyImage(tag) = %v, want a reference-stage refusal", err)
	}
}

// TestRegistryFetchesTheSignatureArtifact drives the HTTP client against a
// fixture server, so the manifest and blob paths are covered without a network.
func TestRegistryFetchesTheSignatureArtifact(t *testing.T) {
	artifact := fixtureArtifact(t)
	manifestData, err := os.ReadFile(filepath.Join("testdata", "signature-manifest.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sum := sha256.Sum256(artifact.Payload)
	blob := "sha256:" + hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/mobley-trent/styx-sandbox/manifests/sha256-"+MustParseRef(ImageRef).Hex()+".sig", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(manifestData)
	})
	mux.HandleFunc("/v2/mobley-trent/styx-sandbox/blobs/"+blob, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(artifact.Payload)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	registry := &Registry{BaseURL: server.URL, Client: server.Client()}
	got, err := registry.Signature(context.Background(), MustParseRef(ImageRef))
	if err != nil {
		t.Fatalf("Signature: %v", err)
	}
	if string(got.Payload) != string(artifact.Payload) {
		t.Errorf("payload did not round trip")
	}
	if string(got.Rekor.SignedEntryTimestamp) != string(artifact.Rekor.SignedEntryTimestamp) {
		t.Errorf("signed entry timestamp did not round trip")
	}
}

func TestEmbeddedTrustedRootCarriesTheLogAndFulcioRoot(t *testing.T) {
	var root struct {
		CTLogs []any `json:"ctlogs"`
		TLogs  []struct {
			LogID struct {
				KeyID string `json:"keyId"`
			} `json:"logId"`
		} `json:"tlogs"`
		CertificateAuthorities []any `json:"certificateAuthorities"`
	}
	if err := json.Unmarshal(TrustedRoot(), &root); err != nil {
		t.Fatalf("embedded trusted root is not JSON: %v", err)
	}
	if len(root.CertificateAuthorities) == 0 || len(root.CTLogs) == 0 || len(root.TLogs) == 0 {
		t.Fatalf("embedded trusted root is incomplete: %+v", root)
	}
	want := fixtureArtifact(t).Rekor.LogID
	found := false
	for _, log := range root.TLogs {
		if log.LogID.KeyID == base64.StdEncoding.EncodeToString(want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("embedded trusted root has no key for the signature's Rekor log")
	}
}
