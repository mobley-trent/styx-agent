package containerlayer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Backend names a host-firewall implementation (§5.2).
type Backend string

const (
	// BackendNFT is the nftables backend. It is preferred: detection tries it
	// first and only falls back to iptables when nft cannot be programmed.
	BackendNFT Backend = "nft"
	// BackendIPTables is the iptables/ip6tables backend.
	BackendIPTables Backend = "iptables"
)

// ErrNoFirewall is the refuse-never-silent error: neither backend could be
// programmed, so the harness must either degrade isolation visibly or refuse
// to run — it must never proceed as if egress were enforced.
var ErrNoFirewall = errors.New(
	"containerlayer: no programmable firewall backend: nft and iptables are both unavailable " +
		"(programming requires CAP_NET_ADMIN; running without it is degraded isolation, not enforced egress)")

// Runner runs one host command. It is the seam the firewall and runtime
// detection share, so rule generation and backend preference are testable
// without a real firewall.
type Runner interface {
	// Run executes args[0] with the remaining arguments, feeding stdin, and
	// returns its combined output. A non-zero exit is a non-nil error.
	Run(ctx context.Context, stdin string, args ...string) (string, error)
}

// EgressSpec is the complete egress policy for one session bridge: the
// interface to scope the rules to, plus every destination the session may
// reach. Everything not listed is dropped (§5.2: "egress allowlist ...
// derived from pins plus model/mirror endpoints").
type EgressSpec struct {
	// Bridge is the host-side interface Docker created for the session
	// network (`--opt com.docker.network.bridge.name=...`). It is what scopes
	// the rules to this session and nothing else.
	Bridge string
	// Allowed is the pinned authorization set plus the run's own endpoints.
	// It is compared as prefixes: IP literals are /32 and /128.
	Allowed []netip.Prefix
}

// normalized returns the spec with its allowed set deduplicated and sorted,
// so identical specs render byte-identical rules.
func (s EgressSpec) normalized() EgressSpec {
	out := s
	out.Allowed = append([]netip.Prefix(nil), s.Allowed...)
	for i, p := range out.Allowed {
		out.Allowed[i] = p.Masked()
	}
	slices.SortFunc(out.Allowed, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	out.Allowed = slices.Compact(out.Allowed)
	return out
}

// Firewall programs one session's egress allowlist and tears it back down.
// Apply and Remove are idempotent enough for the once-per-session lifecycle
// the harness uses; a failed Apply is the signal to degrade isolation.
type Firewall interface {
	// Backend names the implementation.
	Backend() Backend
	// Apply programs the allowlist. A non-nil error means egress is not
	// enforced and the caller must degrade or refuse.
	Apply(ctx context.Context, spec EgressSpec) error
	// Remove deletes the rules. It is best-effort and reports what failed.
	Remove(ctx context.Context, spec EgressSpec) error
}

// DetectFirewall probes for a programmable backend, preferring nft (§5.2:
// "prefer nft backend; detect and fall back"). It returns ErrNoFirewall when
// neither responds, which the session turns into degraded isolation or a
// refusal — never a silent downgrade.
func DetectFirewall(ctx context.Context, r Runner) (Firewall, error) {
	// nft is preferred: `nft list ruleset` both proves the binary exists and
	// that we hold the privilege to program it.
	if _, err := r.Run(ctx, "", "nft", "list", "ruleset"); err == nil {
		return &nftFirewall{runner: r}, nil
	}
	// Fall back to iptables. `iptables -L` is the equivalent probe; it fails
	// without CAP_NET_ADMIN, which is exactly what we need to know.
	if _, err := r.Run(ctx, "", "iptables", "-L", "-n"); err == nil {
		return &iptablesFirewall{runner: r}, nil
	}
	return nil, ErrNoFirewall
}

// nftTable is the nftables table name for a session bridge. Each session owns
// a table, so teardown is a single `delete table` and two consecutive
// sessions can never share rules.
func nftTable(bridge string) string { return "styx_egress_" + bridge }

// nftScript renders the whole nftables transaction for a spec: one table with
// an egress chain holding the allowlist and a forward hook that scopes the
// chain to the session bridge in both directions.
//
// The egress chain accepts established/related traffic, then each allowed
// destination, then drops everything else. The forward hook applies it only to
// packets in or out of the bridge interface, so no other host traffic is
// touched; inbound connections that are not established replies are dropped
// too, so the container has no inbound exposure.
func nftScript(spec EgressSpec) string {
	spec = spec.normalized()
	table := nftTable(spec.Bridge)

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	b.WriteString("\tchain egress {\n")
	b.WriteString("\t\tct state established,related accept\n")
	for _, p := range spec.Allowed {
		switch {
		case p.Addr().Is4():
			fmt.Fprintf(&b, "\t\tip daddr %s accept\n", p.String())
		case p.Addr().Is6():
			fmt.Fprintf(&b, "\t\tip6 daddr %s accept\n", p.String())
		}
	}
	b.WriteString("\t\tdrop\n")
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q jump egress\n", spec.Bridge)
	fmt.Fprintf(&b, "\t\toifname %q jump egress\n", spec.Bridge)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// nftFirewall programs nftables through the `nft` CLI.
type nftFirewall struct {
	runner Runner
}

// Backend implements Firewall.
func (f *nftFirewall) Backend() Backend { return BackendNFT }

// Apply implements Firewall: it creates the session's table in one
// transaction, so a partial rule set can never be live.
func (f *nftFirewall) Apply(ctx context.Context, spec EgressSpec) error {
	if err := validateBridge(spec.Bridge); err != nil {
		return err
	}
	if out, err := f.runner.Run(ctx, nftScript(spec), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("containerlayer: program nft egress rules for %s: %w: %s", spec.Bridge, err, strings.TrimSpace(out))
	}
	return nil
}

// Remove implements Firewall: the whole table goes, so no rule can survive.
func (f *nftFirewall) Remove(ctx context.Context, spec EgressSpec) error {
	if err := validateBridge(spec.Bridge); err != nil {
		return err
	}
	if out, err := f.runner.Run(ctx, "", "nft", "delete", "table", "inet", nftTable(spec.Bridge)); err != nil {
		// A missing table is a clean teardown, not a failure.
		if isAbsent(strings.TrimSpace(out)) {
			return nil
		}
		return fmt.Errorf("containerlayer: remove nft egress rules for %s: %w: %s", spec.Bridge, err, strings.TrimSpace(out))
	}
	return nil
}

// iptablesChain is the per-session chain name in DOCKER-USER. Chain names are
// limited to 28 characters; `STYX_` plus the 10-character bridge hash is 15.
func iptablesChain(bridge string) string {
	suffix := strings.TrimPrefix(bridge, "styx")
	if len(suffix) > 10 {
		suffix = suffix[:10]
	}
	return "STYX_" + strings.ToUpper(suffix)
}

// iptablesRules renders the rule argv vectors for one address family. The
// caller runs each with `iptables` or `ip6tables`. Keeping them as data makes
// the exact policy assertable without a kernel.
//
// The chain is entered from DOCKER-USER in both directions. Established or
// related packets pass; outbound packets to an allowed address pass; inbound
// packets and everything else are dropped. Scoping the jump to the bridge
// means no other host traffic is affected.
func iptablesRules(spec EgressSpec, v6 bool) [][]string {
	spec = spec.normalized()
	chain := iptablesChain(spec.Bridge)
	bridge := spec.Bridge

	out := [][]string{
		{"-N", chain},
		{"-I", "DOCKER-USER", "1", "-i", bridge, "-j", chain},
		{"-I", "DOCKER-USER", "2", "-o", bridge, "-j", chain},
		{"-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"},
	}
	for _, p := range spec.Allowed {
		if p.Addr().Is6() != v6 {
			continue
		}
		out = append(out, []string{"-A", chain, "-d", p.String(), "-j", "RETURN"})
	}
	out = append(out, []string{"-A", chain, "-j", "DROP"})
	return out
}

// iptablesRemoveRules renders the teardown for one address family.
func iptablesRemoveRules(spec EgressSpec) [][]string {
	chain := iptablesChain(spec.Bridge)
	bridge := spec.Bridge
	return [][]string{
		{"-D", "DOCKER-USER", "-i", bridge, "-j", chain},
		{"-D", "DOCKER-USER", "-o", bridge, "-j", chain},
		{"-F", chain},
		{"-X", chain},
	}
}

// iptablesFirewall programs iptables/ip6tables through their CLIs.
type iptablesFirewall struct {
	runner Runner
}

// Backend implements Firewall.
func (f *iptablesFirewall) Backend() Backend { return BackendIPTables }

// Apply implements Firewall. It programs IPv4 through `iptables` and, when the
// allowlist carries IPv6 destinations, IPv6 through `ip6tables`.
func (f *iptablesFirewall) Apply(ctx context.Context, spec EgressSpec) error {
	if err := validateBridge(spec.Bridge); err != nil {
		return err
	}
	if err := f.runAll(ctx, "iptables", iptablesRules(spec, false)); err != nil {
		return err
	}
	if hasV6(spec) {
		if err := f.runAll(ctx, "ip6tables", iptablesRules(spec, true)); err != nil {
			return err
		}
	}
	return nil
}

// Remove implements Firewall. It tears down both families, ignoring vectors
// that were never applied.
func (f *iptablesFirewall) Remove(ctx context.Context, spec EgressSpec) error {
	var errs []error
	if err := f.runAll(ctx, "iptables", iptablesRemoveRules(spec)); err != nil {
		errs = append(errs, err)
	}
	if hasV6(spec) {
		if err := f.runAll(ctx, "ip6tables", iptablesRemoveRules(spec)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// runAll runs each rendered rule vector under program.
func (f *iptablesFirewall) runAll(ctx context.Context, program string, rules [][]string) error {
	for _, rule := range rules {
		args := append([]string{program}, rule...)
		if out, err := f.runner.Run(ctx, "", args...); err != nil {
			if isAbsent(strings.TrimSpace(out)) {
				// Deleting a rule or chain that is already gone (a
				// teardown that ran twice) is success.
				continue
			}
			return fmt.Errorf("containerlayer: %s %s: %w: %s", program, strings.Join(rule, " "), err, strings.TrimSpace(out))
		}
	}
	return nil
}

// hasV6 reports whether the allowlist carries any IPv6 destination.
func hasV6(spec EgressSpec) bool {
	for _, p := range spec.Allowed {
		if p.Addr().Is6() {
			return true
		}
	}
	return false
}

// validateBridge rejects a spec that could program the wrong interface. A
// missing or unexpected bridge name is never quietly accepted: mis-scoped
// rules would silently widen or narrow egress.
func validateBridge(bridge string) error {
	if strings.TrimSpace(bridge) == "" {
		return errors.New("containerlayer: egress spec has no bridge interface")
	}
	if strings.ContainsAny(bridge, " \t\n\"/;") {
		return fmt.Errorf("containerlayer: invalid bridge interface name %q", bridge)
	}
	return nil
}

// isAbsent recognizes the "already gone" messages both backends emit during a
// repeated teardown, so Remove stays idempotent.
func isAbsent(out string) bool {
	l := strings.ToLower(out)
	for _, marker := range []string{
		"no such file or directory",
		"does not exist",
		"no chain/target/match by that name",
		"bad rule",
	} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}
