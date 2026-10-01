// Package config implements configuration: global and project YAML merge
// (project wins), environment-only secrets, and defaults.
//
// Boundary rule: config is loaded once at startup and passed down; it may
// narrow permission defaults but can never weaken ROE hard limits or
// engagement scope checks.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// Compaction mode values (§4.5).
const (
	// ModeAuto fires compaction between turns when the threshold is crossed.
	ModeAuto = "auto"
	// ModeManual leaves compaction to the operator's /compact.
	ModeManual = "manual"
)

// Spec defaults (§10.3, §4.5).
const (
	// DefaultCompactionThreshold is the context-window fraction that fires
	// compaction.
	DefaultCompactionThreshold = 0.85
	// DefaultCompactionKeepTurns is how many recent turns stay verbatim.
	DefaultCompactionKeepTurns = 10
)

// Model is one pinned model in the operator's configuration (§3.1). Model IDs
// are pinned, never aliases, and carry the context-window size the compaction
// trigger rescales from.
type Model struct {
	// ID is the API model ID ("deepseek-flash").
	ID string `yaml:"id"`
	// ContextWindow is the model's context size in tokens.
	ContextWindow int `yaml:"context_window"`
	// InputPerMillion is the peak cache-miss prompt rate, USD per 1M tokens.
	InputPerMillion float64 `yaml:"input_per_million"`
	// OutputPerMillion is the peak completion rate, USD per 1M tokens.
	OutputPerMillion float64 `yaml:"output_per_million"`
	// CacheHitPerMillion is the peak cached-prompt input rate, USD per 1M.
	CacheHitPerMillion float64 `yaml:"cache_hit_per_million"`
}

// Info maps a configured model onto the model layer's descriptor (§3.2).
func (m Model) Info() model.Info {
	return model.Info{
		ID:            m.ID,
		ContextWindow: m.ContextWindow,
		Pricing: model.Pricing{
			InputPerMillion:    m.InputPerMillion,
			OutputPerMillion:   m.OutputPerMillion,
			CacheHitPerMillion: m.CacheHitPerMillion,
		},
	}
}

// Compaction is the §4.5 context-management configuration.
type Compaction struct {
	// Mode is auto or manual.
	Mode string `yaml:"mode"`
	// Threshold is the context-window fraction that fires compaction.
	Threshold float64 `yaml:"threshold"`
	// KeepTurns is how many recent conversation turns stay verbatim.
	KeepTurns int `yaml:"keep_turns"`
}

// Config is the merged, validated configuration: built-in defaults, then the
// global file, then the project file (§10.3: project wins on conflict).
type Config struct {
	// Models is the pinned model set.
	Models []Model
	// Model is the default model ID; it must name one of Models.
	Model string
	// Compaction is the context-management settings.
	Compaction Compaction
	// UpdateNotifier enables the single releases-latest fetch (§12.3).
	UpdateNotifier bool
	// Rules is the project config's permission-rule overlay (§6.1). It may
	// narrow defaults and widen prompts to allows, but never weakens ROE hard
	// limits or engagement scope checks — the policy engine enforces that.
	Rules []policy.Rule
}

// Defaults returns the built-in configuration: the pinned DeepSeek models of
// §3.1 with their published peak pricing (docs/research/2026-09-28-deepseek-api.md),
// auto compaction at the spec's threshold, and the update notifier on.
func Defaults() *Config {
	return &Config{
		Models: []Model{
			{
				ID:                 model.DefaultModelID,
				ContextWindow:      1_000_000,
				InputPerMillion:    0.30,
				OutputPerMillion:   1.20,
				CacheHitPerMillion: 0.006,
			},
			{
				ID:                 "deepseek-v4-pro",
				ContextWindow:      1_000_000,
				InputPerMillion:    1.32,
				OutputPerMillion:   3.96,
				CacheHitPerMillion: 0.044,
			},
		},
		Model: model.DefaultModelID,
		Compaction: Compaction{
			Mode:      ModeAuto,
			Threshold: DefaultCompactionThreshold,
			KeepTurns: DefaultCompactionKeepTurns,
		},
		UpdateNotifier: true,
	}
}

// DefaultGlobalPath is the global config location (§10.3): XDG_CONFIG_HOME
// when set, else ~/.config. It returns "" when no home directory is known.
func DefaultGlobalPath() string {
	if dir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); dir != "" {
		return filepath.Join(dir, "styx", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "styx", "config.yaml")
}

// ProjectPath is the project config overlay location for a project directory
// (§10.3).
func ProjectPath(projectDir string) string {
	return filepath.Join(projectDir, ".styx", "config.yaml")
}

// Load merges the global and project files over Defaults. An empty path is
// skipped; a path that does not exist is not an error (the file is optional),
// but a file that exists and does not parse or validate is. Project values win
// on conflict (§10.3).
func Load(globalPath, projectPath string) (*Config, error) {
	cfg := Defaults()
	for _, path := range []struct{ role, path string }{
		{"global", globalPath},
		{"project", projectPath},
	} {
		if strings.TrimSpace(path.path) == "" {
			continue
		}
		doc, err := readFile(path.path)
		if err != nil {
			return nil, fmt.Errorf("config: %s config %s: %w", path.role, path.path, err)
		}
		if doc == nil {
			continue
		}
		cfg.apply(doc)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// readFile reads one config document. A missing file returns (nil, nil): the
// layer is simply absent. Unknown keys are tolerated by design (the same-major
// compatibility contract, §10.3).
func readFile(path string) (*fileDoc, error) {
	//nolint:gosec // config paths are operator-supplied by design (§10.3).
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var doc fileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return &doc, nil
}

// fileDoc mirrors the on-disk YAML keys. Every field is a pointer or slice so
// "absent" is distinguishable from "set to the zero value": only values the
// operator actually declared override the layer beneath.
type fileDoc struct {
	Model          *string         `yaml:"model"`
	Models         []Model         `yaml:"models"`
	Compaction     *compactionDoc  `yaml:"compaction"`
	UpdateNotifier *bool           `yaml:"update_notifier"`
	Permissions    *permissionsDoc `yaml:"permissions"`
}

// compactionDoc is the partial compaction block: a file may set any subset.
type compactionDoc struct {
	Mode      *string  `yaml:"mode"`
	Threshold *float64 `yaml:"threshold"`
	KeepTurns *int     `yaml:"keep_turns"`
}

// permissionsDoc is the permission-rule overlay (§6.1).
type permissionsDoc struct {
	Rules []ruleDoc `yaml:"rules"`
}

// ruleDoc is one overlay rule keyed on tool name plus a JSON-pointer parameter
// glob (§6.1).
type ruleDoc struct {
	Tool   string `yaml:"tool"`
	Param  string `yaml:"param"`
	Action string `yaml:"action"`
}

// apply overlays one file's declared values onto the config.
func (c *Config) apply(doc *fileDoc) {
	if doc.Models != nil {
		c.Models = append([]Model(nil), doc.Models...)
	}
	if doc.Model != nil {
		c.Model = *doc.Model
	}
	if doc.Compaction != nil {
		if doc.Compaction.Mode != nil {
			c.Compaction.Mode = *doc.Compaction.Mode
		}
		if doc.Compaction.Threshold != nil {
			c.Compaction.Threshold = *doc.Compaction.Threshold
		}
		if doc.Compaction.KeepTurns != nil {
			c.Compaction.KeepTurns = *doc.Compaction.KeepTurns
		}
	}
	if doc.UpdateNotifier != nil {
		c.UpdateNotifier = *doc.UpdateNotifier
	}
	if doc.Permissions != nil {
		// Rules replace wholesale: the project overlay is a complete
		// declaration, not an append (config merge, §10.3).
		c.Rules = make([]policy.Rule, 0, len(doc.Permissions.Rules))
		for _, r := range doc.Permissions.Rules {
			c.Rules = append(c.Rules, policy.Rule{
				Tool:     r.Tool,
				ParamPtr: r.Param,
				Action:   policy.Action(r.Action),
				Source:   "project",
			})
		}
	}
}

// validate rejects a merged config the harness cannot run. It runs after the
// merge so a value from either layer is checked once.
func (c *Config) validate() error {
	if len(c.Models) == 0 {
		return errors.New("config: models: at least one pinned model is required")
	}
	seen := make(map[string]bool, len(c.Models))
	for i, m := range c.Models {
		if strings.TrimSpace(m.ID) == "" {
			return fmt.Errorf("config: models[%d]: id is required", i)
		}
		if seen[m.ID] {
			return fmt.Errorf("config: models: duplicate model ID %q", m.ID)
		}
		seen[m.ID] = true
		if m.ContextWindow <= 0 {
			return fmt.Errorf("config: models[%d] (%s): context_window must be positive", i, m.ID)
		}
	}
	if c.Model == "" {
		return errors.New("config: model: a default model ID is required")
	}
	if !seen[c.Model] {
		return fmt.Errorf("config: model %q is not in the pinned model set", c.Model)
	}
	switch c.Compaction.Mode {
	case ModeAuto, ModeManual:
	default:
		return fmt.Errorf("config: compaction.mode %q: want %q or %q", c.Compaction.Mode, ModeAuto, ModeManual)
	}
	if c.Compaction.Threshold <= 0 || c.Compaction.Threshold > 1 {
		return fmt.Errorf("config: compaction.threshold %v: want a fraction in (0, 1]", c.Compaction.Threshold)
	}
	if c.Compaction.KeepTurns < 0 {
		return fmt.Errorf("config: compaction.keep_turns %d: must not be negative", c.Compaction.KeepTurns)
	}
	for i, r := range c.Rules {
		if strings.TrimSpace(r.Tool) == "" {
			return fmt.Errorf("config: permissions.rules[%d]: tool is required", i)
		}
		switch r.Action {
		case policy.VerdictAllow, policy.VerdictPrompt, policy.VerdictDeny:
		default:
			return fmt.Errorf("config: permissions.rules[%d] (%s): action %q: want allow, prompt, or deny", i, r.Tool, r.Action)
		}
	}
	return nil
}

// ModelInfo returns the pinned model set in the model layer's shape (§3.2).
func (c *Config) ModelInfo() []model.Info {
	infos := make([]model.Info, 0, len(c.Models))
	for _, m := range c.Models {
		infos = append(infos, m.Info())
	}
	return infos
}

// ModelByID returns the configured model with the given ID.
func (c *Config) ModelByID(id string) (Model, bool) {
	for _, m := range c.Models {
		if m.ID == id {
			return m, true
		}
	}
	return Model{}, false
}
