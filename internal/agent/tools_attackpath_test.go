package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// attackPathFixture is a minimal record: one foothold pivoting to one host.
func attackPathFixture() engagementstate.Snapshot {
	return engagementstate.Snapshot{
		SchemaVersion: engagementstate.SchemaVersion,
		Entities: []engagementstate.Entity{
			{
				ID: "access-0001", Kind: engagementstate.KindAccess, Active: true,
				Target: "host-0001", Level: engagementstate.LevelUser,
			},
			{ID: "host-0001", Kind: engagementstate.KindHost, Active: true, Addresses: []string{"10.0.0.1"}},
			{ID: "host-0002", Kind: engagementstate.KindHost, Active: true, Addresses: []string{"10.0.0.2"}},
		},
		Edges: []engagementstate.Edge{
			{
				Type: engagementstate.EdgePivotTo, From: "access-0001", To: "host-0002",
				Confidence: engagementstate.ConfidenceHigh,
			},
		},
	}
}

func TestAttackPathToolRendersTheComputation(t *testing.T) {
	store := &fakeStateStore{snapshotResult: attackPathFixture()}
	tool := AttackPathTool(store)

	out, err := tool.Handler(context.Background(), map[string]any{"target": "10.0.0.2"})
	if err != nil {
		t.Fatalf("handler() = %v", err)
	}
	for _, want := range []string{"attack paths to host-0002", "cost 20", "pivot"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q should contain %q", out, want)
		}
	}
}

func TestAttackPathToolRefusesUnusableCalls(t *testing.T) {
	cases := []struct {
		name  string
		store StateStore
		args  map[string]any
		want  string
	}{
		{
			name:  "no engagement",
			store: nil,
			args:  map[string]any{"target": "host-0002"},
			want:  "needs an active engagement",
		},
		{
			name:  "missing target",
			store: &fakeStateStore{snapshotResult: attackPathFixture()},
			args:  map[string]any{},
			want:  "missing required argument",
		},
		{
			name:  "blank target",
			store: &fakeStateStore{snapshotResult: attackPathFixture()},
			args:  map[string]any{"target": "  "},
			want:  "target is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AttackPathTool(tc.store).Handler(context.Background(), tc.args)
			if err == nil {
				t.Fatalf("handler(%s) = nil error, want a refusal", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal %q should mention %q", err, tc.want)
			}
		})
	}
}

func TestAttackPathSchemaHasOneRequiredProperty(t *testing.T) {
	var schema struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
		Additional *bool          `json:"additionalProperties"`
	}
	if err := json.Unmarshal(AttackPathTool(nil).Parameters, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if len(schema.Properties) != 1 {
		t.Errorf("properties = %v, want exactly target", schema.Properties)
	}
	if _, ok := schema.Properties["target"]; !ok {
		t.Errorf("properties = %v, want target", schema.Properties)
	}
	if len(schema.Required) != 1 || schema.Required[0] != "target" {
		t.Errorf("required = %v, want [target]", schema.Required)
	}
	if schema.Additional == nil || *schema.Additional {
		t.Errorf("additionalProperties = %v, want false", schema.Additional)
	}
}
