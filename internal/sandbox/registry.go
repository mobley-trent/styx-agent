package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SignatureArtifact is the signature published beside an image: cosign's legacy
// `.sig` artifact, flattened out of its OCI annotations so a cached copy is
// self-contained (docs/sandbox-image.md §6.1–§6.2).
type SignatureArtifact struct {
	// Payload is the simple-signing document the signature covers.
	Payload []byte `json:"payload"`
	// Signature is the raw signature over Payload.
	Signature []byte `json:"signature"`
	// Certificate is the signing certificate, DER.
	Certificate []byte `json:"certificate"`
	// Chain is the rest of the certificate chain, DER, leaf excluded.
	Chain [][]byte `json:"chain"`
	// Rekor is the transparency-log entry the signer obtained.
	Rekor RekorBundle `json:"rekor"`
}

// RekorBundle is the transparency-log material cosign publishes beside a
// signature: the entry body, its position, and Rekor's signed entry timestamp.
type RekorBundle struct {
	SignedEntryTimestamp []byte `json:"signed_entry_timestamp"`
	Body                 []byte `json:"body"`
	IntegratedTime       int64  `json:"integrated_time"`
	LogIndex             int64  `json:"log_index"`
	LogID                []byte `json:"log_id"`
}

// BundleSource fetches the signature artifact for a digest-pinned reference.
// The production implementation is Registry; tests substitute a fixture, so no
// test touches the network.
type BundleSource interface {
	Signature(ctx context.Context, ref Ref) (SignatureArtifact, error)
}

// registryTimeout bounds one registry round trip, so an unresponsive registry
// fails with a clear error instead of hanging the session start.
const registryTimeout = 60 * time.Second

// Registry reads the signature artifact cosign attaches to an image
// (docs/sandbox-image.md §6.1). It speaks to the registry anonymously over
// HTTPS: the signature lives in a separate OCI artifact, so only that artifact
// and its blobs are fetched — the image bytes are pulled by the container
// runtime afterwards, and only once verification has passed.
type Registry struct {
	// BaseURL overrides the registry base URL (tests point it at an httptest
	// server). Empty derives it from the reference's host.
	BaseURL string
	// Client is the HTTP client. Nil means a bounded default.
	Client *http.Client
}

// Signature implements BundleSource.
func (r *Registry) Signature(ctx context.Context, ref Ref) (SignatureArtifact, error) {
	manifest, err := r.manifest(ctx, ref)
	if err != nil {
		return SignatureArtifact{}, err
	}
	if len(manifest.Layers) != 1 {
		return SignatureArtifact{}, fmt.Errorf("signature artifact has %d layers, want exactly 1", len(manifest.Layers))
	}
	payload, err := r.blob(ctx, ref, manifest.Layers[0].Digest)
	if err != nil {
		return SignatureArtifact{}, err
	}
	// The layer digest is the content address of the payload: a registry that
	// served different bytes than it advertised is refused here, before the
	// payload's signature is even considered.
	sum := sha256.Sum256(payload)
	if want := "sha256:" + hex.EncodeToString(sum[:]); want != manifest.Layers[0].Digest {
		return SignatureArtifact{}, fmt.Errorf("signature payload digest %s does not match the manifest's %s", want, manifest.Layers[0].Digest)
	}
	return artifactFromAnnotations(manifest.Layers[0].Annotations, payload)
}

// ociLayer is the part of an OCI descriptor the signature artifact uses.
type ociLayer struct {
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	MediaType   string            `json:"mediaType"`
	Annotations map[string]string `json:"annotations"`
}

// ociManifest is the signature artifact's manifest.
type ociManifest struct {
	MediaType string     `json:"mediaType"`
	Layers    []ociLayer `json:"layers"`
}

// manifest fetches the signature artifact's manifest, named by the cosign tag
// convention `sha256-<hex>.sig` (§6.1).
func (r *Registry) manifest(ctx context.Context, ref Ref) (ociManifest, error) {
	host, path := ref.Host()
	url := fmt.Sprintf("%s/v2/%s/manifests/sha256-%s.sig", r.baseURL(host), path, ref.Hex())
	body, err := r.get(ctx, ref, url, "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return ociManifest{}, fmt.Errorf("fetch signature manifest: %w", err)
	}
	var m ociManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return ociManifest{}, fmt.Errorf("parse signature manifest: %w", err)
	}
	return m, nil
}

// blob fetches one blob by digest.
func (r *Registry) blob(ctx context.Context, ref Ref, digest string) ([]byte, error) {
	host, path := ref.Host()
	url := fmt.Sprintf("%s/v2/%s/blobs/%s", r.baseURL(host), path, digest)
	body, err := r.get(ctx, ref, url, "application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("fetch signature payload: %w", err)
	}
	return body, nil
}

// get performs one anonymous registry request, acquiring a bearer token first.
func (r *Registry) get(ctx context.Context, ref Ref, url, accept string) ([]byte, error) {
	token, err := r.token(ctx, ref)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, registryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// token acquires an anonymous pull token for the repository.
func (r *Registry) token(ctx context.Context, ref Ref) (string, error) {
	if r.BaseURL != "" {
		// A test server needs no token, and asking for one would be a
		// different request than the fixture serves.
		return "", nil
	}
	host, path := ref.Host()
	// authURL is the registry's anonymous-credential endpoint, not a secret.
	service, authURL := host, "https://"+host+"/token"
	if host == "docker.io" {
		service, authURL = "registry.docker.io", "https://auth.docker.io/token"
	}
	endpoint := authURL + "?service=" + url.QueryEscape(service) + "&scope=" + url.QueryEscape("repository:"+path+":pull")

	ctx, cancel := context.WithTimeout(ctx, registryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("registry token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token: %s", resp.Status)
	}
	var out struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("registry token: %w", err)
	}
	if out.Token != "" {
		return out.Token, nil
	}
	if out.AccessToken != "" {
		return out.AccessToken, nil
	}
	return "", fmt.Errorf("registry token: empty token for %s", path)
}

// baseURL is the registry's API base: the test override, else the host's.
func (r *Registry) baseURL(host string) string {
	if r.BaseURL != "" {
		return strings.TrimRight(r.BaseURL, "/")
	}
	if host == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + host
}

func (r *Registry) httpClient() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: registryTimeout}
}

// cosign's annotation keys on the signature artifact's layer (§6.1).
const (
	annotationSignature   = "dev.cosignproject.cosign/signature"
	annotationCertificate = "dev.sigstore.cosign/certificate"
	annotationChain       = "dev.sigstore.cosign/chain"
	annotationRekorBundle = "dev.sigstore.cosign/bundle"
)

// legacyRekor is the transparency-log bundle cosign publishes in an annotation.
type legacyRekor struct {
	SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// artifactFromAnnotations flattens a cosign signature artifact into the
// self-contained form verification and the cache work with.
func artifactFromAnnotations(annotations map[string]string, payload []byte) (SignatureArtifact, error) {
	if len(annotations) == 0 {
		return SignatureArtifact{}, fmt.Errorf("signature artifact carries no annotations")
	}
	sig, err := decodeBase64(annotations[annotationSignature])
	if err != nil || len(sig) == 0 {
		return SignatureArtifact{}, fmt.Errorf("signature artifact has no usable %s annotation", annotationSignature)
	}
	certPEM := annotations[annotationCertificate]
	if strings.TrimSpace(certPEM) == "" {
		return SignatureArtifact{}, fmt.Errorf("signature artifact has no %s annotation", annotationCertificate)
	}
	leaf, chain, err := parseCertificateChain(certPEM + "\n" + annotations[annotationChain])
	if err != nil {
		return SignatureArtifact{}, err
	}
	var rekor legacyRekor
	if err := json.Unmarshal([]byte(annotations[annotationRekorBundle]), &rekor); err != nil {
		return SignatureArtifact{}, fmt.Errorf("signature artifact's %s annotation: %w", annotationRekorBundle, err)
	}
	set, err := decodeBase64(rekor.SignedEntryTimestamp)
	if err != nil || len(set) == 0 {
		return SignatureArtifact{}, fmt.Errorf("signature artifact has no usable signed entry timestamp")
	}
	body, err := decodeBase64(rekor.Payload.Body)
	if err != nil || len(body) == 0 {
		return SignatureArtifact{}, fmt.Errorf("signature artifact has no usable transparency-log entry body")
	}
	logID, err := hex.DecodeString(rekor.Payload.LogID)
	if err != nil || len(logID) == 0 {
		return SignatureArtifact{}, fmt.Errorf("signature artifact has no usable transparency-log id")
	}
	return SignatureArtifact{
		Payload:     payload,
		Signature:   sig,
		Certificate: leaf,
		Chain:       chain,
		Rekor: RekorBundle{
			SignedEntryTimestamp: set,
			Body:                 body,
			IntegratedTime:       rekor.Payload.IntegratedTime,
			LogIndex:             rekor.Payload.LogIndex,
			LogID:                logID,
		},
	}, nil
}

// parseCertificateChain parses the leaf certificate and the chain that follows
// it. One PEM block is a leaf with no rest of chain; a block that is not a
// certificate is an error, never a silently ignored entry.
func parseCertificateChain(pemData string) ([]byte, [][]byte, error) {
	var certs [][]byte
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("signature artifact carries a %q block, not a certificate", block.Type)
		}
		certs = append(certs, block.Bytes)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("signature artifact carries no certificate")
	}
	return certs[0], certs[1:], nil
}

// decodeBase64 decodes cosign's standard base64 annotation values.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	return base64.StdEncoding.DecodeString(s)
}
