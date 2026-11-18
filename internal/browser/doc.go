// Package browser is the harness's host browser: a pinned Chromium launched as
// a subprocess, driven over CDP, with one profile per engagement and the
// session's artifacts under `.styx/out/`.
//
// Boundary rule: browser owns the browser process and its CDP traffic. It never
// decides scope — the tool's Targets and the harness proxy's per-request checks
// do (docs/browser-and-proxy.md §3.3, §4.2) — and it never widens what the
// model can see: reads return an aria snapshot of the DOM, never a cookie,
// storage value, or Authorization header (§3.6).
//
// The browser is a host prerequisite, resolved and version-checked before every
// launch (§3.1): an absent or different build is a named error, never a silent
// downgrade. It launches with `--proxy-server` at the harness proxy and QUIC
// and WebRTC's non-proxied UDP disabled, so no second egress path exists. CDP
// is bound to a random loopback port that is never placed on the command line,
// and the harness reaches it through a per-launch token gate on its own loopback
// listener. A crash is a named transport error; the next call relaunches with
// the same profile, cookies included (§8).
//
// One browser per session, one active page (§7). The profile outlives the
// session for an engagement and is guarded by a pid-checked lockfile; safe mode
// has no engagement to scope a profile to, so it gets an ephemeral one that is
// deleted at session end (§5).
package browser
