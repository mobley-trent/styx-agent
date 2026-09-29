// Package config implements configuration: global and project YAML merge
// (project wins), environment-only secrets, and defaults.
//
// Boundary rule: config is loaded once at startup and passed down; it may
// narrow permission defaults but can never weaken ROE hard limits or
// engagement scope checks.
package config
