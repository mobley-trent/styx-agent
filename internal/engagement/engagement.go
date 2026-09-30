package engagement

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// APIVersion is the only engagement-file schema version this build accepts
// (§7.1: `apiVersion: styx.engagement/v1`). Any other version refuses to
// start — an unknown schema must never be interpreted on a best-effort basis.
const APIVersion = "styx.engagement/v1"

// Refusal reasons. Load and Parse wrap exactly one of these for every
// rejection, so callers can branch — and tests can assert — on the kind of
// refusal without matching message text.
var (
	// ErrParse is a file that does not parse or does not match the §7.1
	// schema: malformed YAML, unknown fields, a missing or unsupported
	// apiVersion, a malformed expiry, or more than one YAML document.
	ErrParse = errors.New("engagement: malformed file")
	// ErrStale is a file whose expiry has passed (§7.2: "stale = refuse to
	// start"). Absent expiry means evergreen; it is never stale.
	ErrStale = errors.New("engagement: expired")
	// ErrTarget is an unusable authorization pool: no targets at all, a
	// malformed target, a target that does not resolve, or a wildcard whose
	// expansion cannot be pinned.
	ErrTarget = errors.New("engagement: invalid target")
	// ErrROE is a missing, malformed, or unusable rules-of-engagement block.
	ErrROE = errors.New("engagement: invalid roe")
)

// document is the §7.1 on-disk schema. The field tags are the YAML keys; the
// decoder runs with KnownFields on, so anything outside this shape — a typo'd
// top-level key, an expressive-but-unenforced ROE flag — is a malformed file
// rather than a silently ignored key.
type document struct {
	APIVersion string   `yaml:"apiVersion"`
	Name       string   `yaml:"name"`
	Operator   string   `yaml:"operator"`
	Expires    string   `yaml:"expires"`
	Targets    []string `yaml:"targets"`
	ROE        roeDoc   `yaml:"roe"`
}

// roeDoc is the machine-checked ROE flag set (§7.1: "nothing
// expressive-but-unenforced"). The flags are pointers so the loader can tell
// "declared false" from "absent": an omitted safety flag is refused rather
// than defaulted, because the zero value of destructive_forbidden is the
// fail-open one (§6.3).
type roeDoc struct {
	ExploitAllowed       *bool      `yaml:"exploit_allowed"`
	DestructiveForbidden *bool      `yaml:"destructive_forbidden"`
	TimeWindow           *windowDoc `yaml:"time_window"`
}

// windowDoc is the optional ROE time window (§7.1). TZ is an IANA location
// name and defaults to UTC when omitted.
type windowDoc struct {
	Start string `yaml:"start"`
	End   string `yaml:"end"`
	TZ    string `yaml:"tz"`
}

// Engagement is a validated engagement file: the single flat authorization
// pool with its load-time DNS pins, plus the ROE limits the policy engine
// binds (§7.1, §7.2). It is immutable after Load/Parse returns.
type Engagement struct {
	name     string
	operator string
	expires  *time.Time
	targets  []string
	scope    *Scope
	roe      *policy.ROE
}

// Name is the file's label ("appears in TUI + audit entries"; §7.1).
func (e *Engagement) Name() string { return e.name }

// Operator is the informational operator name from the file. It is recorded
// in the audit trail and is not an authorization mechanism (§7.1).
func (e *Engagement) Operator() string { return e.operator }

// Expires reports the file's expiry and whether one was declared. Absent
// means evergreen.
func (e *Engagement) Expires() (time.Time, bool) {
	if e.expires == nil {
		return time.Time{}, false
	}
	return *e.expires, true
}

// Targets returns the pool entries exactly as the file declared them
// (advisory; §7.4). Enforcement uses Scope.
func (e *Engagement) Targets() []string {
	return append([]string(nil), e.targets...)
}

// Scope is the pinned authorization pool. It satisfies policy.Scope, so the
// engine consumes it without this package leaking into policy (§2).
func (e *Engagement) Scope() *Scope { return e.scope }

// ROE is the engagement's rules-of-engagement limits (§6.3).
func (e *Engagement) ROE() *policy.ROE { return e.roe }

// Option configures Load and Parse.
type Option func(*config)

// config carries the injectable seams: the resolver (DNS) and the clock
// (expiry). Both are production defaults unless a test replaces them.
type config struct {
	resolver Resolver
	now      func() time.Time
}

func newConfig(opts []Option) *config {
	c := &config{resolver: DefaultResolver, now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithResolver replaces the DNS seam. Tests pin hostnames deterministically;
// production keeps the host resolver.
func WithResolver(r Resolver) Option {
	return func(c *config) {
		if r != nil {
			c.resolver = r
		}
	}
}

// WithClock replaces the loader's clock. Expiry is the only thing it reads
// (§7.2: "stale = refuse to start").
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// Load reads, validates, and pins an engagement file. Any problem refuses to
// start: the file must parse, every target must resolve, the ROE flags must
// come from the closed v1 set, and a stale expiry is fatal (§7.2). A refusal
// returns a nil Engagement — there are no partial scopes.
func Load(ctx context.Context, path string, opts ...Option) (*Engagement, error) {
	//nolint:gosec // the engagement file path is operator-supplied by design (§7.2).
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("engagement: read %s: %w", path, err)
	}
	eng, err := Parse(ctx, data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return eng, nil
}

// Parse validates and pins an engagement file's bytes without touching the
// filesystem. It is the whole gate: Load adds only the read. Every rejection
// wraps one of ErrParse, ErrStale, ErrTarget, or ErrROE, and every problem in
// the file is reported (joined), not just the first.
func Parse(ctx context.Context, data []byte, opts ...Option) (*Engagement, error) {
	doc, err := decode(data)
	if err != nil {
		return nil, err
	}
	return build(ctx, doc, newConfig(opts))
}

// decode unmarshals the file strictly: unknown fields are errors, and a
// second YAML document is an error (a file is one declaration, not a stream).
func decode(data []byte) (*document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var doc document
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: file is empty", ErrParse)
		}
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}

	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	case !nullNode(&extra):
		return nil, fmt.Errorf("%w: file has more than one YAML document", ErrParse)
	}
	return &doc, nil
}

// nullNode reports whether a decoded node carries no content (an empty
// trailing `---` document is not a second declaration).
func nullNode(n *yaml.Node) bool {
	if n.Kind == 0 {
		return true
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return true
		}
		return nullNode(n.Content[0])
	}
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Value == "")
}

// build validates the document and pins its pool. It collects every problem
// so a file with several mistakes is fixed once; any problem at all means no
// Engagement is returned.
func build(ctx context.Context, doc *document, cfg *config) (*Engagement, error) {
	var errs []error

	if doc.APIVersion != APIVersion {
		errs = append(errs, fmt.Errorf("%w: apiVersion %q: want %q", ErrParse, doc.APIVersion, APIVersion))
	}
	if strings.TrimSpace(doc.Name) == "" {
		errs = append(errs, fmt.Errorf("%w: name: required (the label audit entries carry)", ErrParse))
	}

	var expires *time.Time
	if raw := strings.TrimSpace(doc.Expires); raw != "" {
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: expires %q: want an RFC 3339 timestamp", ErrParse, doc.Expires))
		} else {
			expires = &at
			if !cfg.now().Before(at) {
				errs = append(errs, fmt.Errorf("%w: %s (now %s)", ErrStale,
					at.UTC().Format(time.RFC3339), cfg.now().UTC().Format(time.RFC3339)))
			}
		}
	}

	entries, targetErrs := parseTargets(ctx, cfg.resolver, doc.Targets)
	errs = append(errs, targetErrs...)
	roe, roeErrs := parseROE(&doc.ROE)
	errs = append(errs, roeErrs...)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &Engagement{
		name:     strings.TrimSpace(doc.Name),
		operator: strings.TrimSpace(doc.Operator),
		expires:  expires,
		targets:  append([]string(nil), doc.Targets...),
		scope:    &Scope{entries: entries},
		roe:      roe,
	}, nil
}

// parseTargets turns the declared pool into pinned entries, reporting every
// unusable entry at once: malformed entries and unresolvable targets are
// collected together so the operator fixes the file once. The returned
// entries are only used when there is no error, so a refused file never
// yields a partial pool.
func parseTargets(ctx context.Context, r Resolver, targets []string) ([]entry, []error) {
	if len(targets) == 0 {
		return nil, []error{fmt.Errorf("%w: targets: at least one is required", ErrTarget)}
	}

	entries := make([]entry, 0, len(targets))
	var errs []error
	for _, raw := range targets {
		e, err := parseTarget(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entries = append(entries, e)
	}

	pinned := make([]entry, 0, len(entries))
	for _, e := range entries {
		if !e.needsResolve() {
			pinned = append(pinned, e)
			continue
		}
		resolved, err := pin(ctx, r, e)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		pinned = append(pinned, resolved)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return pinned, nil
}

// parseROE validates the closed v1 flag set and maps it onto the policy
// engine's ROE. Both flags must be declared: the schema's zero values are not
// safe defaults (absent exploit_allowed means "off" but absent
// destructive_forbidden means "destructive allowed"), so ambiguity is refused
// instead of guessed.
func parseROE(doc *roeDoc) (*policy.ROE, []error) {
	var errs []error
	if doc.ExploitAllowed == nil {
		errs = append(errs, fmt.Errorf("%w: roe.exploit_allowed: required (false forbids exploit-class tooling)", ErrROE))
	}
	if doc.DestructiveForbidden == nil {
		errs = append(errs, fmt.Errorf("%w: roe.destructive_forbidden: required (true forbids destructive-tagged calls)", ErrROE))
	}

	var window *policy.TimeWindow
	if doc.TimeWindow != nil {
		if err := doc.TimeWindow.validate(); err != nil {
			errs = append(errs, err)
		} else {
			window = &policy.TimeWindow{
				Start: doc.TimeWindow.Start,
				End:   doc.TimeWindow.End,
				TZ:    doc.TimeWindow.TZ,
			}
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return &policy.ROE{
		ExploitAllowed:       *doc.ExploitAllowed,
		DestructiveForbidden: *doc.DestructiveForbidden,
		TimeWindow:           window,
	}, nil
}

// validate checks the window is usable at load, not at first denied call: a
// malformed window is a file defect and refuses to start (§7.2). The parser
// here matches the policy engine's expectations — "HH:MM" wall clock and a
// loadable IANA zone — so an accepted file can never fail at decision time.
func (w *windowDoc) validate() error {
	if _, err := time.Parse("15:04", w.Start); err != nil {
		return fmt.Errorf("%w: roe.time_window.start %q: want HH:MM", ErrROE, w.Start)
	}
	if _, err := time.Parse("15:04", w.End); err != nil {
		return fmt.Errorf("%w: roe.time_window.end %q: want HH:MM", ErrROE, w.End)
	}
	if w.TZ != "" {
		if _, err := time.LoadLocation(w.TZ); err != nil {
			return fmt.Errorf("%w: roe.time_window.tz %q: unknown IANA time zone", ErrROE, w.TZ)
		}
	}
	return nil
}

// parseTarget classifies one pool entry (§7.1): an IP literal, a CIDR, a
// hostname, or a wildcard domain of the `*.acme.example` form. Resolution is
// a separate step; this function is pure.
func parseTarget(raw string) (entry, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return entry{}, fmt.Errorf("%w: %q: empty entry", ErrTarget, raw)
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		if ip.Zone() != "" {
			return entry{}, fmt.Errorf("%w: %q: a scoped IPv6 address is a local interface, not an authorization target", ErrTarget, raw)
		}
		return entry{raw: raw, kind: entryIP, ip: ip.Unmap()}, nil
	}
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return entry{}, fmt.Errorf("%w: %q: not an IP or CIDR (%w)", ErrTarget, raw, err)
		}
		return entry{raw: raw, kind: entryCIDR, cidr: prefix.Masked()}, nil
	}

	host := normalizeName(s)
	kind := entryHost
	switch {
	case host == "*" || (strings.Contains(host, "*") && !strings.HasPrefix(host, "*.")):
		return entry{}, fmt.Errorf("%w: %q: a wildcard must be of the form *.example.com", ErrTarget, raw)
	case strings.HasPrefix(host, "*."):
		kind = entryWildcard
		host = strings.TrimPrefix(host, "*.")
	}
	if err := validHostname(host); err != nil {
		return entry{}, fmt.Errorf("%w: %q: %w", ErrTarget, raw, err)
	}
	if kind == entryWildcard {
		return entry{raw: raw, kind: kind, name: "*." + host}, nil
	}
	return entry{raw: raw, kind: kind, name: host}, nil
}

// validHostname rejects names a resolver cannot meaningfully answer for. It
// is deliberately permissive about shape (single-label hosts, underscores)
// because the pool's authority is the resolution that follows, not the
// spelling.
func validHostname(host string) error {
	if host == "" {
		return errors.New("empty hostname")
	}
	if len(host) > 253 {
		return errors.New("hostname longer than 253 characters")
	}
	for _, label := range strings.Split(host, ".") {
		switch {
		case label == "":
			return errors.New("empty label")
		case len(label) > 63:
			return fmt.Errorf("label %q longer than 63 characters", label)
		case strings.HasPrefix(label, "-"), strings.HasSuffix(label, "-"):
			return fmt.Errorf("label %q starts or ends with '-'", label)
		}
		for _, r := range label {
			ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
			if !ok {
				return fmt.Errorf("invalid character %q in label %q", r, label)
			}
		}
	}
	return nil
}

// pin resolves one hostname (or wildcard) entry once, at load, and stores the
// addresses as the entry's immutable pin set (§7.2: "resolved IPs are
// pinned"). The wildcard name is queried as declared; the resolver is the
// seam, so a deployment whose resolver cannot answer wildcard names refuses
// the file at load rather than silently widening or narrowing scope.
func pin(ctx context.Context, r Resolver, e entry) (entry, error) {
	addrs, err := r.LookupHost(ctx, e.name)
	if err != nil {
		return entry{}, fmt.Errorf("%w: %q: cannot pin: %w", ErrTarget, e.raw, err)
	}
	if len(addrs) == 0 {
		return entry{}, fmt.Errorf("%w: %q: resolves to no addresses", ErrTarget, e.raw)
	}

	seen := make(map[netip.Addr]bool, len(addrs))
	pins := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil {
			return entry{}, fmt.Errorf("%w: %q: resolver returned %q, not an address", ErrTarget, e.raw, a)
		}
		ip = ip.Unmap()
		if !seen[ip] {
			seen[ip] = true
			pins = append(pins, ip)
		}
	}
	sortAddrs(pins)
	e.pins = pins
	return e, nil
}
