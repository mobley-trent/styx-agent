package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/diff"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/policy"
)

// Handler executes an admitted tool call: it runs only after schema
// validation, the policy verdict, and the audit write (§5.3).
type Handler func(ctx context.Context, args map[string]any) (string, error)

// Tool is one named, schema-described capability the model may invoke (§5.1).
// Its descriptor is what the model sees; its handler is what the harness runs.
// Destructive and ExploitClass are the tags the ROE hard limits bind to
// (§6.3) — only the registry sets them, never inferred from arguments.
type Tool struct {
	// Name is the tool's wire name.
	Name string
	// Description is the model-facing description.
	Description string
	// Parameters is the tool's JSON Schema object.
	Parameters json.RawMessage
	// Destructive tags the call as destructive (§6.3, §8.3). Only the
	// registry sets this.
	Destructive bool
	// ExploitClass tags the call as exploit-class tooling (§6.3).
	ExploitClass bool
	// Handler runs the call.
	Handler Handler
	// Preview computes a diff-class tool's proposed change without applying
	// it (§9.2). It is non-nil only on the write/edit tools; the loop renders
	// and reviews the diff, then calls Handler only on acceptance. A nil
	// Preview means the tool is not diff-class and Handler runs directly.
	Preview func(args map[string]any) (*diff.FileDiff, error)
	// Targets maps the call's arguments onto the concrete destinations it
	// intends to touch (§7.2). Pure file tools leave it nil.
	Targets func(args map[string]any) []policy.Target
}

// Descriptor is the tool's descriptor as the model sees it. Built-in tools
// are always strict (§3.3).
func (t Tool) Descriptor() model.Tool {
	return model.Tool{
		Name:        t.Name,
		Description: t.Description,
		Parameters:  t.Parameters,
		Strict:      true,
	}
}

// Registry is the loop's tool set: the descriptors exposed to the model and
// the handlers the harness dispatches. It is immutable after construction.
type Registry struct {
	order []string
	tools map[string]Tool
}

// NewRegistry builds a registry. A tool with an empty name, a duplicate name,
// or no handler is rejected — a silently missing handler would surface as a
// mystery failure at dispatch time.
func NewRegistry(tools ...Tool) (*Registry, error) {
	r := &Registry{tools: make(map[string]Tool, len(tools))}
	for _, t := range tools {
		if t.Name == "" {
			return nil, fmt.Errorf("agent: tool with an empty name")
		}
		if t.Handler == nil {
			return nil, fmt.Errorf("agent: tool %q has no handler", t.Name)
		}
		if _, dup := r.tools[t.Name]; dup {
			return nil, fmt.Errorf("agent: duplicate tool %q", t.Name)
		}
		r.tools[t.Name] = t
		r.order = append(r.order, t.Name)
	}
	return r, nil
}

// Lookup returns the tool with the given name.
func (r *Registry) Lookup(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// Names returns the registered tool names in registration order.
func (r *Registry) Names() []string { return append([]string(nil), r.order...) }

// Descriptors returns the model-facing descriptors, in registration order.
func (r *Registry) Descriptors() []model.Tool {
	out := make([]model.Tool, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.tools[name].Descriptor())
	}
	return out
}
