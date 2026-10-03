// Package mcpclient implements external capabilities through one gate: MCP
// servers configured per project, launched over stdio via the official Go SDK,
// their tools exposed as ordinary descriptors.
//
// Boundary rule: mcpclient is a transport and a registry — it discovers and
// calls tools, and it reports connection lifecycle. It contains no policy
// logic: every MCP tool call passes the same policy engine, audit trail, and
// schema validation as a built-in (docs/spec.md §5.3, §5.5). The harness, not
// the server, is what validates arguments.
package mcpclient
