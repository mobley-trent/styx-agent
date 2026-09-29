// Package containerlayer owns per-session containers: bridge setup, egress
// allowlist, fallback egress proxy, and DNS pinning at the container edge.
//
// Boundary rule: containerlayer is the ONLY package that touches the host
// network stack (Docker networking, nft/iptables, the fallback proxy).
// Nothing else knows the mechanism — only the guarantee: egress equals
// pinned scope, or visibly degraded isolation.
package containerlayer
