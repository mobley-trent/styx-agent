package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// writeConfig writes a config file under dir and returns its path.
func writeConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultsAreValid(t *testing.T) {
	cfg := Defaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("Defaults().validate() = %v, want nil", err)
	}
	if cfg.Model != "deepseek-flash" {
		t.Errorf("default model = %q, want deepseek-flash", cfg.Model)
	}
	if cfg.Compaction.Mode != ModeAuto || cfg.Compaction.Threshold != DefaultCompactionThreshold || cfg.Compaction.KeepTurns != DefaultCompactionKeepTurns {
		t.Errorf("default compaction = %+v, want auto/%v/%d", cfg.Compaction, DefaultCompactionThreshold, DefaultCompactionKeepTurns)
	}
	if !cfg.UpdateNotifier {
		t.Error("update notifier default = false, want true")
	}
	if got := (Model{ID: "x", ContextWindow: 1}).Info().ID; got != "x" {
		t.Errorf("Model.Info().ID = %q, want x", got)
	}
}

func TestLoadMissingFilesYieldDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"), "")
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if cfg.Model != Defaults().Model {
		t.Errorf("model = %q, want the default", cfg.Model)
	}
}

func TestProjectOverridesGlobal(t *testing.T) {
	dir := t.TempDir()
	global := writeConfig(t, dir, "global.yaml", `
compaction:
  threshold: 0.9
  keep_turns: 5
model: deepseek-v4-pro
update_notifier: false
`)
	project := writeConfig(t, dir, "project.yaml", `
compaction:
  keep_turns: 3
update_notifier: true
`)
	cfg, err := Load(global, project)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	// Global values survive where the project says nothing.
	if cfg.Compaction.Threshold != 0.9 {
		t.Errorf("threshold = %v, want 0.9 (global)", cfg.Compaction.Threshold)
	}
	if cfg.Model != "deepseek-v4-pro" {
		t.Errorf("model = %q, want the global override", cfg.Model)
	}
	// Project wins on conflict.
	if cfg.Compaction.KeepTurns != 3 {
		t.Errorf("keep_turns = %d, want 3 (project)", cfg.Compaction.KeepTurns)
	}
	if !cfg.UpdateNotifier {
		t.Error("update_notifier = false, want true (project)")
	}
}

func TestProjectReplacesModelSet(t *testing.T) {
	dir := t.TempDir()
	global := writeConfig(t, dir, "global.yaml", `
model: deepseek-flash
`)
	project := writeConfig(t, dir, "project.yaml", `
models:
  - id: local-model
    context_window: 128000
model: local-model
`)
	cfg, err := Load(global, project)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if len(cfg.Models) != 1 || cfg.Models[0].ID != "local-model" {
		t.Fatalf("models = %+v, want the project's single pinned model", cfg.Models)
	}
	if got := cfg.ModelInfo()[0].ContextWindow; got != 128000 {
		t.Errorf("context window = %d, want 128000", got)
	}
}

func TestLoadToleratesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", `
model: deepseek-flash
some_future_key: whatever
compaction:
  mode: manual
  future_subkey: 1
`)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() = %v, want nil (unknown keys are additive, §10.3)", err)
	}
	if cfg.Compaction.Mode != ModeManual {
		t.Errorf("mode = %q, want manual", cfg.Compaction.Mode)
	}
}

func TestLoadPermissionRules(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", `
permissions:
  rules:
    - tool: bash
      param: command
      action: deny
    - tool: write_file
      action: allow
`)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(cfg.Rules))
	}
	if cfg.Rules[0].Tool != "bash" || cfg.Rules[0].ParamPtr != "command" || cfg.Rules[0].Action != policy.VerdictDeny {
		t.Errorf("rule[0] = %+v, want bash/command/deny", cfg.Rules[0])
	}
	if cfg.Rules[0].Source != "project" {
		t.Errorf("rule source = %q, want project", cfg.Rules[0].Source)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "not yaml", body: "model: [unterminated\n"},
		{name: "unknown default model", body: "model: nope\n"},
		{name: "empty model id", body: "models:\n  - id: \"\"\n    context_window: 1\nmodel: deepseek-flash\n"},
		{name: "bad compaction mode", body: "compaction:\n  mode: sometimes\n"},
		{name: "bad threshold", body: "compaction:\n  threshold: 1.5\n"},
		{name: "negative keep turns", body: "compaction:\n  keep_turns: -1\n"},
		{name: "bad rule action", body: "permissions:\n  rules:\n    - tool: bash\n      action: maybe\n"},
		{name: "rule without tool", body: "permissions:\n  rules:\n    - action: allow\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, t.TempDir(), "config.yaml", tt.body)
			if _, err := Load(path, ""); err == nil {
				t.Errorf("Load(%s) = nil error, want a validation error", tt.name)
			}
		})
	}
}

func TestContainerConfigMergesAndValidates(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", `
container:
  image: registry.example/styx:1
  egress_allow:
    - 203.0.113.0/24
    - 198.51.100.7
`)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.Container.Image != "registry.example/styx:1" {
		t.Errorf("container image = %q, want the declared image", cfg.Container.Image)
	}
	if len(cfg.Container.EgressAllow) != 2 {
		t.Errorf("egress_allow = %v, want both entries", cfg.Container.EgressAllow)
	}

	bad := writeConfig(t, t.TempDir(), "config.yaml", "container:\n  egress_allow:\n    - not-an-address\n")
	if _, err := Load(bad, ""); err == nil {
		t.Error("Load(bad egress) = nil error, want an unparseable widening rejected")
	}
}

func TestMCPConfigLoadsAndValidates(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "config.yaml", `
mcp:
  servers:
    - name: nmap
      command: nmap-mcp
      args: ["--fast"]
      env: ["NMAP_TOKEN=abc"]
    - name: ghidra
      command: ghidra-mcp
      disabled: true
`)
	cfg, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.MCP.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(cfg.MCP.Servers))
	}
	if cfg.MCP.Servers[0].Name != "nmap" || cfg.MCP.Servers[0].Command != "nmap-mcp" {
		t.Errorf("server[0] = %+v, want nmap/nmap-mcp", cfg.MCP.Servers[0])
	}
	if len(cfg.MCP.Servers[0].Args) != 1 || cfg.MCP.Servers[0].Args[0] != "--fast" {
		t.Errorf("server[0] args = %v, want [--fast]", cfg.MCP.Servers[0].Args)
	}
	// Enabled filters the disabled server without dropping it.
	enabled := cfg.MCP.Enabled()
	if len(enabled) != 1 || enabled[0].Name != "nmap" {
		t.Errorf("Enabled() = %+v, want only nmap", enabled)
	}
}

func TestMCPConfigRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing name", body: "mcp:\n  servers:\n    - command: nmap-mcp\n"},
		{name: "missing command", body: "mcp:\n  servers:\n    - name: nmap\n"},
		{name: "duplicate name", body: "mcp:\n  servers:\n    - name: nmap\n      command: a\n    - name: nmap\n      command: b\n"},
		{name: "bad env", body: "mcp:\n  servers:\n    - name: nmap\n      command: nmap-mcp\n      env: [\"NOT_A_PAIR\"]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, t.TempDir(), "config.yaml", tt.body)
			if _, err := Load(path, ""); err == nil {
				t.Errorf("Load(%s) = nil error, want a validation error", tt.name)
			}
		})
	}
}

func TestDefaultPaths(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got, want := DefaultGlobalPath(), filepath.Join("/xdg", "styx", "config.yaml"); got != want {
		t.Errorf("DefaultGlobalPath() = %q, want %q", got, want)
	}
	if got, want := ProjectPath("/repo"), filepath.Join("/repo", ".styx", "config.yaml"); got != want {
		t.Errorf("ProjectPath() = %q, want %q", got, want)
	}
}
