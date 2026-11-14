// Package containerlayer owns per-session containers: bridge setup, egress
// allowlist, the egress and interception proxy, PKI custody for it, and DNS
// pinning at the container edge.
//
// Boundary rule: containerlayer is the ONLY package that touches the host
// network stack (Docker networking, nft/iptables, the proxy). Nothing else
// knows the mechanism — only the guarantee: egress equals pinned scope, or
// visibly degraded isolation.
//
// The proxy has two shapes (docs/browser-and-proxy.md §4.2). Without
// InterceptOptions it is the safe-mode egress path: a plain CONNECT tunnel
// with no capture, because there is no pinned scope to enforce and nothing to
// attribute a capture to. With them it is the engagement's interception
// proxy: CONNECT is terminated with the engagement's CA, every request is
// re-resolved against the pinned scope, every exchange is captured and
// replayable, and a scope refusal is a structured 403 plus an audit entry —
// never a prompt, because a tunnel has no in-flight call to raise a card on.
package containerlayer
