// Package engagement implements the engagement file: load, strict
// refuse-to-start validation, scope pins, and DNS pinning.
//
// Boundary rule: engagement authorizes scope only — never tool rules; it
// feeds the policy engine and containerlayer, and unparseable or stale files
// refuse to start rather than degrade.
package engagement
