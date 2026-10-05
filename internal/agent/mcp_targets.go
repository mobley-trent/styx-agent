package agent

import (
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/naming"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// mcpTargetNames are the parameter-name tokens that mark an argument as a
// network destination (§5.5, §7.2). Matching is token-based — camelCase and
// separators split the name — so `targetHost` and `ip_address` match while
// `recipient` (which merely contains the letters "ip") does not.
var mcpTargetNames = map[string]bool{
	"target": true, "targets": true,
	"host": true, "hosts": true,
	"hostname": true, "hostnames": true,
	"ip": true, "ips": true,
	"address": true, "addresses": true, "addr": true, "addrs": true,
	"cidr":    true,
	"network": true, "networks": true,
	"url": true, "urls": true,
	"endpoint": true, "endpoints": true,
	"domain": true, "domains": true,
	"destination": true, "destinations": true, "dest": true, "dests": true,
	"scope": true,
}

// mcpScopeTargets derives the concrete network destinations an MCP tool call
// intends to touch, from its arguments (§5.5: an MCP tool passes the same
// policy gate as a built-in, scope check included). It is the MCP analogue of
// WebFetchTool's and SSHLogsTool's Targets functions: without it the engine
// sees an empty target set and resolves the call through the rule table only,
// never through scope.
//
// Arguments whose name is target-ish (`target`, `host`, `url`, …) contribute
// their string values verbatim; nested objects and arrays are flattened.
// When no target-ish name is present, only values that are unambiguously
// destinations (an IP literal, a CIDR, or an absolute http(s) URL) are taken,
// so arbitrary prose is never mistaken for a target.
func mcpScopeTargets(args map[string]any) []policy.Target {
	if len(args) == 0 {
		return nil
	}
	// Iterate keys in a stable order: Go's map order is random, and a call's
	// target list must be reproducible for the audit trail and tests.
	keys := make([]string, 0, len(args))
	for key := range args {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var addrs []string
	matched := false
	for _, key := range keys {
		if !nameHasTargetToken(key) {
			continue
		}
		matched = true
		addrs = append(addrs, extractAddrs(args[key], true)...)
	}
	if !matched {
		for _, key := range keys {
			addrs = append(addrs, extractAddrs(args[key], false)...)
		}
	}
	return dedupeTargets(addrs)
}

// extractAddrs pulls destination strings out of a decoded JSON value. trusted
// is true under a target-named key, where any non-empty string counts; false
// elsewhere, where a string must look like a destination to count.
func extractAddrs(val any, trusted bool) []string {
	switch v := val.(type) {
	case string:
		if trusted {
			return []string{normalizeTarget(v)}
		}
		if looksLikeDestination(v) {
			return []string{normalizeTarget(v)}
		}
		return nil
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, extractAddrs(e, trusted)...)
		}
		return out
	case map[string]any:
		// Inside an object the keys are unknown, so only unambiguous
		// destinations count regardless of how the object was reached.
		var out []string
		for _, e := range v {
			out = append(out, extractAddrs(e, false)...)
		}
		return out
	default:
		return nil
	}
}

// normalizeTarget reduces a raw destination to the host the scope matches on:
// an absolute URL contributes its host, and a `user@host:port` form loses its
// user and port. Anything else is returned trimmed.
func normalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		return sshTargetHost(u.Host)
	}
	return sshTargetHost(s)
}

// looksLikeDestination reports whether a bare string is unambiguously a
// network destination: an IP literal, a CIDR block, or an absolute http(s)
// URL. It gates the fallback path, where there is no target-ish name to lean
// on.
func looksLikeDestination(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if u, err := url.Parse(s); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		return true
	}
	return false
}

// dedupeTargets turns extracted addresses into policy targets, dropping empty
// values and duplicates while preserving order.
func dedupeTargets(addrs []string) []policy.Target {
	seen := make(map[string]bool, len(addrs))
	var out []policy.Target
	for _, a := range addrs {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, policy.Target{Addr: a})
	}
	return out
}

// nameHasTargetToken reports whether a parameter name contains a target-ish
// token.
func nameHasTargetToken(name string) bool {
	for _, tok := range naming.Tokens(name) {
		if mcpTargetNames[tok] {
			return true
		}
	}
	return false
}
