package containerlayer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// CA custody (§4.4). One certification authority per engagement, at
// <pki root>/<project>/<engagement>/ca.pem with its key beside it at 0600,
// created on first use and reused for the engagement's life. The key never
// leaves that directory: it is never logged, never captured, and never a tool
// result.
const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"

	caCertMode = 0o644
	caKeyMode  = 0o600
	caDirMode  = 0o700

	// caLifetime is long enough that an engagement never loses trust mid-run;
	// rotation is the operator's act, like deleting the store.
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 30 * 24 * time.Hour
	leafBackdate = time.Hour
)

// DefaultPKIRoot is the PKI root (§4.4, §10.4):
// $XDG_DATA_HOME/styx/pki, else ~/.local/share/styx/pki — alongside the
// session and engagement-state stores, never inside the repo. It returns ""
// when no home directory is known.
func DefaultPKIRoot() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dir != "" {
		return filepath.Join(dir, "styx", "pki")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "share", "styx", "pki")
}

// CAOptions configures OpenCA.
type CAOptions struct {
	// Root is the PKI root; empty means DefaultPKIRoot.
	Root string
	// ProjectDir is the engagement's project directory. Its directory
	// component is derived exactly as the session store derives it, so two
	// checkouts named alike never share a CA.
	ProjectDir string
	// Engagement is the engagement name. Its directory component is derived
	// exactly as the engagement-state store derives it.
	Engagement string
	// Now stamps the certificate; nil means time.Now.
	Now func() time.Time
}

// CA is one engagement's issuing authority: it signs the leaves the
// interception proxy presents for intercepted hosts. It is safe for
// concurrent use; leaves are cached per host.
type CA struct {
	dir    string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	now    func() time.Time
	issued bool

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// OpenCA loads — or creates on first use — the engagement's CA. An existing
// certificate whose key is missing or belongs to a different public key is an
// error naming both files: a CA that cannot sign is never silently replaced.
func OpenCA(opts CAOptions) (*CA, error) {
	root := strings.TrimSpace(opts.Root)
	if root == "" {
		root = DefaultPKIRoot()
	}
	if root == "" {
		return nil, errors.New("containerlayer: no PKI root (no home directory)")
	}
	if strings.TrimSpace(opts.ProjectDir) == "" {
		return nil, errors.New("containerlayer: a CA needs the engagement's project directory")
	}
	if strings.TrimSpace(opts.Engagement) == "" {
		return nil, errors.New("containerlayer: a CA needs an engagement name")
	}

	dir := filepath.Join(root, sessions.ProjectKey(opts.ProjectDir), engagementstate.EngagementKey(opts.Engagement))
	//nolint:gosec // the path is derived from the store root and sanitized names.
	if err := os.MkdirAll(dir, caDirMode); err != nil {
		return nil, fmt.Errorf("containerlayer: create PKI directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, caDirMode); err != nil {
		return nil, fmt.Errorf("containerlayer: restrict PKI directory %s: %w", dir, err)
	}

	ca := &CA{dir: dir, now: opts.Now, leaves: map[string]*tls.Certificate{}}
	if ca.now == nil {
		ca.now = time.Now
	}

	certPath, keyPath := ca.CertPath(), ca.KeyPath()
	switch _, certErr := os.Stat(certPath); {
	case certErr == nil:
		cert, key, err := loadCA(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		ca.cert, ca.key = cert, key
	case errors.Is(certErr, os.ErrNotExist):
		// A key without a certificate is a torn first use: the certificate is
		// the anchor, so it is regenerated and the stale key replaced.
		cert, key, err := createCA(ca.now(), dir)
		if err != nil {
			return nil, err
		}
		ca.cert, ca.key, ca.issued = cert, key, true
	default:
		return nil, fmt.Errorf("containerlayer: inspect CA %s: %w", certPath, certErr)
	}
	return ca, nil
}

// Dir is the engagement's PKI directory.
func (c *CA) Dir() string { return c.dir }

// CertPath is the CA certificate's path, the file a container trusts (§4.4).
func (c *CA) CertPath() string { return filepath.Join(c.dir, caCertFile) }

// KeyPath is the CA private key's path, mode 0600 (§4.4).
func (c *CA) KeyPath() string { return filepath.Join(c.dir, caKeyFile) }

// Created reports whether this call created the CA, so the caller can audit
// the decision (§9).
func (c *CA) Created() bool { return c.issued }

// CertPEM is the CA certificate in PEM form.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// Pool is a certificate pool holding only this CA, for a client that should
// trust exactly the engagement's interception.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// Leaf issues — or returns from cache — the certificate the proxy presents for
// one host. A literal IP gets an IP SAN; anything else gets a DNS SAN.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if host == "" {
		return nil, errors.New("containerlayer: an interception leaf needs a host")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: generate leaf key for %s: %w", host, err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              now.Add(leafLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		tmpl.IPAddresses = []net.IP{net.IP(ip.Unmap().AsSlice())}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: sign leaf for %s: %w", host, err)
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}
	c.leaves[host] = leaf
	return leaf, nil
}

// loadCA reads an existing certificate and key, refusing a pair that does not
// belong together.
func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	//nolint:gosec // the path is derived from the PKI root and sanitized names.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: read CA certificate %s: %w", certPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("containerlayer: %s is not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: parse CA certificate %s: %w", certPath, err)
	}

	//nolint:gosec // the path is derived from the PKI root and sanitized names.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: read CA key %s (the certificate at %s cannot sign without it): %w", keyPath, certPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("containerlayer: %s is not a PEM private key", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: parse CA key %s: %w", keyPath, err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("containerlayer: CA key %s does not match the certificate %s", keyPath, certPath)
	}
	return cert, key, nil
}

// createCA mints a new engagement CA and writes it into dir. The key is
// written first, so an interrupted first use leaves an incomplete pair the
// next call regenerates rather than a certificate whose key is gone.
func createCA(now time.Time, dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: generate CA key: %w", err)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: encode CA public key: %w", err)
	}
	keyID := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "styx interception CA", Organization: []string{"styx"}},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: parse created CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("containerlayer: encode CA key: %w", err)
	}
	keyPath := filepath.Join(dir, caKeyFile)
	//nolint:gosec // the path is derived from the PKI root and sanitized names.
	if err := writePEMFile(keyPath, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}, caKeyMode); err != nil {
		return nil, nil, err
	}
	//nolint:gosec // the path is derived from the PKI root and sanitized names.
	if err := writePEMFile(filepath.Join(dir, caCertFile), &pem.Block{Type: "CERTIFICATE", Bytes: der}, caCertMode); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// writePEMFile writes one PEM block atomically, so a crash never leaves a
// half-written key or certificate behind.
func writePEMFile(path string, block *pem.Block, mode os.FileMode) error {
	//nolint:gosec // the directory is the engagement's PKI directory, not caller-controlled.
	f, err := os.CreateTemp(filepath.Dir(path), ".pki-*")
	if err != nil {
		return fmt.Errorf("containerlayer: create %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("containerlayer: restrict %s: %w", path, err)
	}
	if err := pem.Encode(f, block); err != nil {
		_ = f.Close()
		return fmt.Errorf("containerlayer: write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("containerlayer: sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("containerlayer: close %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("containerlayer: install %s: %w", path, err)
	}
	return nil
}

// serialNumber returns a random 128-bit certificate serial (§ RFC 5280 §4.1.2.2).
func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("containerlayer: generate certificate serial: %w", err)
	}
	return serial, nil
}
