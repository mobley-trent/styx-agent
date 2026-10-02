package agent

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// Prompt sections are data, never Go string literals (§2): the prompt golden
// snapshots and the future eval seam both depend on the prompt being
// assembled from files.
//
//go:embed promptdata/identity.md
var identitySection string

//go:embed promptdata/harness.md
var harnessSection string

//go:embed promptdata/coding.md
var codingSection string

//go:embed promptdata/engagement.md.tmpl
var engagementTemplate string

//go:embed promptdata/memory.md.tmpl
var memoryTemplate string

// EngagementContext is the advisory scope summary the harness injects into
// the system prompt when an engagement is active (§7.4). It is enforcement's
// shadow, never its substitute: the policy engine and the container egress
// layer are what actually bound the run.
type EngagementContext struct {
	// Name is the engagement file's label.
	Name string
	// Targets is the authorization pool exactly as declared (advisory).
	Targets []string
	// ExploitAllowed mirrors roe.exploit_allowed.
	ExploitAllowed bool
	// DestructiveForbidden mirrors roe.destructive_forbidden.
	DestructiveForbidden bool
	// Expires is the rendered expiry, empty when the file is evergreen.
	Expires string
	// TimeWindow is the rendered ROE time window ("08:00–18:00
	// America/New_York"), empty when the file declares none.
	TimeWindow string
}

// PromptInput is everything the byte-stable prefix is assembled from (§3.3,
// §7.4). It is fixed at session start and never mutated mid-session, so
// DeepSeek's exact-prefix cache stays warm.
type PromptInput struct {
	// Mode is the harness mode the session started in.
	Mode policy.Mode
	// Engagement is the active engagement's scope summary, nil in safe mode.
	Engagement *EngagementContext
	// Memory is the project's STYX.md contents, empty when absent.
	Memory string
}

// BuildSystemPrompt renders the system prompt, the head of the byte-stable
// prefix. Sections are separated by a blank line and appear in a fixed order:
// identity, working rules, engagement context, project memory, coding
// workflow. Swap nothing in place — a change to this string is a change to
// the cache prefix and to the golden snapshot.
func BuildSystemPrompt(in PromptInput) (string, error) {
	sections := []string{identitySection, harnessSection}

	if in.Engagement != nil {
		rendered, err := render(engagementTemplate, in.Engagement)
		if err != nil {
			return "", err
		}
		sections = append(sections, rendered)
	}
	if memory := strings.TrimSpace(in.Memory); memory != "" {
		rendered, err := render(memoryTemplate, map[string]string{"Content": memory})
		if err != nil {
			return "", err
		}
		sections = append(sections, rendered)
	}

	sections = append(sections, codingSection)

	trimmed := make([]string, 0, len(sections))
	for _, s := range sections {
		if t := strings.Trim(s, "\n"); t != "" {
			trimmed = append(trimmed, t)
		}
	}
	// A trailing newline: the prompt is a document, and the separator between
	// sections is exactly one blank line.
	return strings.Join(trimmed, "\n\n") + "\n", nil
}

// render executes one embedded template.
func render(src string, data any) (string, error) {
	tmpl, err := template.New("section").Parse(src)
	if err != nil {
		return "", fmt.Errorf("agent: parse prompt template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("agent: render prompt section: %w", err)
	}
	return buf.String(), nil
}
