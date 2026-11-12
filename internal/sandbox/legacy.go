package sandbox

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

// legacyBundleMediaType is the bundle version cosign's `.sig` artifact
// corresponds to: verification material, a message signature over the
// simple-signing payload, and a transparency-log entry carrying an inclusion
// promise (the signed entry timestamp) rather than an inclusion proof. It is
// what sigstore-go accepts for offline, promise-only entries.
const legacyBundleMediaType = "application/vnd.dev.sigstore.bundle+json;version=0.1"

// hashedrekordKindVersion is the Rekor entry type a cosign image signature is
// logged as.
const (
	hashedrekordKind    = "hashedrekord"
	hashedrekordVersion = "0.0.1"
)

// protobundleFor converts cosign's legacy artifact into the bundle sigstore-go
// verifies. The message signature covers the simple-signing payload, exactly as
// cosign signed it; the payload's own claim is checked separately against the
// pinned digest (verifyClaim).
func protobundleFor(a SignatureArtifact) (*protobundle.Bundle, []byte, error) {
	if len(a.Payload) == 0 || len(a.Signature) == 0 || len(a.Certificate) == 0 {
		return nil, nil, fmt.Errorf("signature artifact is incomplete")
	}
	if len(a.Rekor.SignedEntryTimestamp) == 0 || len(a.Rekor.Body) == 0 || len(a.Rekor.LogID) == 0 {
		return nil, nil, fmt.Errorf("signature artifact has no transparency-log entry")
	}
	payloadDigest := sha256.Sum256(a.Payload)

	certificates := []*protocommon.X509Certificate{{RawBytes: a.Certificate}}
	for _, der := range a.Chain {
		certificates = append(certificates, &protocommon.X509Certificate{RawBytes: der})
	}

	bundle := &protobundle.Bundle{
		MediaType: legacyBundleMediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{Certificates: certificates},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{{
				LogIndex:       a.Rekor.LogIndex,
				LogId:          &protocommon.LogId{KeyId: a.Rekor.LogID},
				KindVersion:    &protorekor.KindVersion{Kind: hashedrekordKind, Version: hashedrekordVersion},
				IntegratedTime: a.Rekor.IntegratedTime,
				InclusionPromise: &protorekor.InclusionPromise{
					SignedEntryTimestamp: a.Rekor.SignedEntryTimestamp,
				},
				CanonicalizedBody: a.Rekor.Body,
			}},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    payloadDigest[:],
				},
				Signature: a.Signature,
			},
		},
	}
	return bundle, payloadDigest[:], nil
}

// simpleSigning is the payload cosign signs for an image: the claim that a
// digest was signed, and the digest itself.
type simpleSigning struct {
	Critical struct {
		Type  string `json:"type"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
	} `json:"critical"`
}

// verifyClaim checks that the signed payload claims the digest being verified.
// The signature proves *some* payload was signed by the trusted workflow; this
// is what binds that payload to the image a session is about to pull.
func verifyClaim(payload []byte, ref Ref) error {
	var claim simpleSigning
	if err := json.Unmarshal(payload, &claim); err != nil {
		return fmt.Errorf("signed payload is not a simple-signing document: %w", err)
	}
	if claim.Critical.Type != "cosign container image signature" {
		return fmt.Errorf("signed payload is a %q, not an image signature", claim.Critical.Type)
	}
	if got := claim.Critical.Image.DockerManifestDigest; got != ref.Digest {
		return fmt.Errorf("signature covers %s, not the pinned %s", got, ref.Digest)
	}
	return nil
}

// encodeArtifact renders an artifact as the cache stores it.
func encodeArtifact(a SignatureArtifact) ([]byte, error) {
	return json.MarshalIndent(a, "", "  ")
}

// decodeArtifact reads an artifact back from the cache.
func decodeArtifact(data []byte) (SignatureArtifact, error) {
	var a SignatureArtifact
	if err := json.Unmarshal(data, &a); err != nil {
		return SignatureArtifact{}, fmt.Errorf("trust cache: %w", err)
	}
	if len(a.Payload) == 0 || len(a.Signature) == 0 || len(a.Certificate) == 0 {
		return SignatureArtifact{}, fmt.Errorf("trust cache: artifact is incomplete")
	}
	return a, nil
}
