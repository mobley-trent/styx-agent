package containerlayer

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func prefixesFor(t *testing.T, entries ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p)
			continue
		}
		ip, err := netip.ParseAddr(e)
		if err != nil {
			t.Fatalf("bad test address %q: %v", e, err)
		}
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	return out
}

func TestDetectFirewallPrefersNFT(t *testing.T) {
	runner := &fakeRunner{available: map[string]bool{"nft": true, "iptables": true}}
	fw, err := DetectFirewall(context.Background(), runner)
	if err != nil {
		t.Fatalf("DetectFirewall() = %v", err)
	}
	if fw.Backend() != BackendNFT {
		t.Errorf("backend = %q, want nft (preferred)", fw.Backend())
	}
	// iptables must not have been probed once nft answered.
	for _, call := range runner.calls {
		if call[0] == "iptables" {
			t.Errorf("iptables was probed despite nft being available: %v", call)
		}
	}
}

func TestDetectFirewallFallsBackToIPTables(t *testing.T) {
	runner := &fakeRunner{available: map[string]bool{"iptables": true}}
	fw, err := DetectFirewall(context.Background(), runner)
	if err != nil {
		t.Fatalf("DetectFirewall() = %v", err)
	}
	if fw.Backend() != BackendIPTables {
		t.Errorf("backend = %q, want iptables fallback", fw.Backend())
	}
}

func TestDetectFirewallRefusesNeverSilent(t *testing.T) {
	runner := &fakeRunner{available: map[string]bool{}}
	fw, err := DetectFirewall(context.Background(), runner)
	if fw != nil {
		t.Fatalf("DetectFirewall() = %v, want nil when no backend is available", fw)
	}
	if !errors.Is(err, ErrNoFirewall) {
		t.Fatalf("DetectFirewall() error = %v, want ErrNoFirewall", err)
	}
}

func TestNFTScriptScopesToBridgeAndDefaultsDrop(t *testing.T) {
	spec := EgressSpec{
		Bridge:  "styx0a1b2c3d4e",
		Allowed: prefixesFor(t, "10.0.0.0/24", "2001:db8::1"),
	}
	script := nftScript(spec)

	for _, want := range []string{
		"table inet " + nftTable(spec.Bridge),
		`iifname "styx0a1b2c3d4e" jump egress`,
		`oifname "styx0a1b2c3d4e" jump egress`,
		"ip daddr 10.0.0.0/24 accept",
		"ip6 daddr 2001:db8::1/128 accept",
		"drop",
		"ct state established,related accept",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("nft script is missing %q:\n%s", want, script)
		}
	}
}

func TestIPTablesRulesScopeBothDirectionsAndDrop(t *testing.T) {
	spec := EgressSpec{
		Bridge:  "styx0a1b2c3d4e",
		Allowed: prefixesFor(t, "10.0.0.0/24", "2001:db8::1"),
	}
	chain := iptablesChain(spec.Bridge)
	if chain != "STYX_0A1B2C3D4E" {
		t.Fatalf("chain = %q, want the bridge-derived STYX_ name", chain)
	}

	v4 := iptablesRules(spec, false)
	joined := joinRules(v4)
	for _, want := range []string{
		"-N " + chain,
		"-I DOCKER-USER 1 -i styx0a1b2c3d4e -j " + chain,
		"-I DOCKER-USER 2 -o styx0a1b2c3d4e -j " + chain,
		"-A " + chain + " -d 10.0.0.0/24 -j RETURN",
		"-A " + chain + " -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("iptables rules are missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "2001:db8::1") {
		t.Errorf("IPv6 destination leaked into the IPv4 rules:\n%s", joined)
	}
	if !strings.Contains(joinRules(iptablesRules(spec, true)), "-d 2001:db8::1/128 -j RETURN") {
		t.Errorf("IPv6 rules are missing the IPv6 destination")
	}
}

func TestValidateBridgeRejectsEmptyAndInjection(t *testing.T) {
	for _, bridge := range []string{"", "  ", "styx0; rm -rf /", `styx"evil`} {
		if err := validateBridge(bridge); err == nil {
			t.Errorf("validateBridge(%q) = nil, want an error", bridge)
		}
	}
	if err := validateBridge("styx0a1b2c3d4e"); err != nil {
		t.Errorf("validateBridge(valid) = %v", err)
	}
}

// joinRules flattens rule vectors for substring assertions.
func joinRules(rules [][]string) string {
	var b strings.Builder
	for _, rule := range rules {
		b.WriteString(strings.Join(rule, " "))
		b.WriteByte('\n')
	}
	return b.String()
}
