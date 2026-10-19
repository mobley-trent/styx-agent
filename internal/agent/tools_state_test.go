package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// fakeStateStore records the calls the state tools make.
type fakeStateStore struct {
	queries     []engagementstate.Query
	queryResult engagementstate.Snapshot
	queryErr    error

	origins []engagementstate.Origin
	ops     [][]engagementstate.Op
	receipt engagementstate.Receipt
	update  error
}

func (f *fakeStateStore) Query(q engagementstate.Query) (engagementstate.Snapshot, error) {
	f.queries = append(f.queries, q)
	return f.queryResult, f.queryErr
}

func (f *fakeStateStore) Update(_ context.Context, origin engagementstate.Origin, ops []engagementstate.Op) (engagementstate.Receipt, error) {
	f.origins = append(f.origins, origin)
	f.ops = append(f.ops, ops)
	return f.receipt, f.update
}

func TestStateQueryParsesFilters(t *testing.T) {
	store := &fakeStateStore{queryResult: engagementstate.Snapshot{Revision: 3}}
	tool := StateQueryTool(store)

	out, err := tool.Handler(context.Background(), map[string]any{
		"kind":             "service",
		"id":               "",
		"where_json":       `{"port":445,"state":"OPEN"}`,
		"hops":             1,
		"include_inactive": false,
		"limit":            25,
	})
	if err != nil {
		t.Fatalf("handler() = %v", err)
	}
	if !strings.Contains(out, "state revision 3") {
		t.Errorf("output = %q, want the rendered snapshot", out)
	}
	if len(store.queries) != 1 {
		t.Fatalf("queries = %d, want 1", len(store.queries))
	}
	q := store.queries[0]
	if q.Kind != engagementstate.KindService || q.Hops != 1 || q.Limit != 25 || q.IncludeInactive {
		t.Errorf("query = %+v, want the call's filters", q)
	}
	if q.Where["port"] != "445" || q.Where["state"] != "OPEN" {
		t.Errorf("where = %+v, want the decoded filters", q.Where)
	}
}

func TestStateQueryRefusesUnusableArguments(t *testing.T) {
	store := &fakeStateStore{}
	tool := StateQueryTool(store)

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{
			name: "hops without a selection",
			args: map[string]any{"kind": "", "id": "", "where_json": "", "hops": 2, "include_inactive": false, "limit": 0},
			want: "hops needs a selection",
		},
		{
			name: "where_json is not an object",
			args: map[string]any{"kind": "", "id": "", "where_json": "[1,2]", "hops": 0, "include_inactive": false, "limit": 0},
			want: "where_json",
		},
		{
			name: "where_json with a nested value",
			args: map[string]any{"kind": "", "id": "", "where_json": `{"state":{"nested":true}}`, "hops": 0, "include_inactive": false, "limit": 0},
			want: "want a string, number, or boolean",
		},
		{
			name: "missing argument",
			args: map[string]any{"kind": "host"},
			want: "missing required argument",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tool.Handler(context.Background(), tc.args)
			if err == nil {
				t.Fatalf("handler(%s) = nil error, want a refusal", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal %q should mention %q", err, tc.want)
			}
		})
	}
	// A refused call never reaches the store.
	if len(store.queries) != 0 {
		t.Errorf("queries = %d, want none: every case above is refused before the store", len(store.queries))
	}
}

func TestStateUpdateDecodesOpsAndStampsOrigin(t *testing.T) {
	store := &fakeStateStore{receipt: engagementstate.Receipt{
		Revision: 2,
		Effects:  []engagementstate.Effect{{Op: engagementstate.OpUpsertEntity, Kind: "host", ID: "host-1a2b", Created: true}},
	}}
	tool := StateUpdateTool(store)

	ctx := withOrigin(context.Background(), "recon")
	out, err := tool.Handler(ctx, map[string]any{
		"ops_json": `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"]}]`,
	})
	if err != nil {
		t.Fatalf("handler() = %v", err)
	}
	if !strings.Contains(out, `"revision":2`) || !strings.Contains(out, `"id":"host-1a2b"`) {
		t.Errorf("receipt = %q, want the encoded receipt", out)
	}
	if len(store.origins) != 1 {
		t.Fatalf("updates = %d, want 1", len(store.origins))
	}
	if store.origins[0].Tool != StateUpdateToolName || store.origins[0].Subagent != "recon" {
		t.Errorf("origin = %+v, want state_update attributed to the recon run", store.origins[0])
	}
	if len(store.ops[0]) != 1 || store.ops[0][0].Kind != engagementstate.KindHost {
		t.Errorf("ops = %+v, want the decoded batch", store.ops[0])
	}

	// A batch whose JSON is refused never reaches the store.
	if _, err := tool.Handler(ctx, map[string]any{"ops_json": `[{"op":"upsert_entity","kind":"host","source":"nmap"}]`}); err == nil {
		t.Errorf("model-supplied provenance should be refused")
	}
	if len(store.origins) != 1 {
		t.Errorf("a refused batch must not reach the store")
	}
}

func TestStateToolsRefuseWithoutEngagementState(t *testing.T) {
	for _, tool := range []Tool{StateQueryTool(nil), StateUpdateTool(nil)} {
		args := map[string]any{"kind": "", "id": "", "where_json": "", "hops": 0, "include_inactive": false, "limit": 0}
		if tool.Name == StateUpdateToolName {
			args = map[string]any{"ops_json": `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"]}]`}
		}
		_, err := tool.Handler(context.Background(), args)
		if err == nil || !strings.Contains(err.Error(), "engagement") {
			t.Errorf("%s without a store = %v, want an engagement refusal", tool.Name, err)
		}
	}

	// The tools carry no scope targets and no safety tags: they are a
	// rule-table matter, never a scope question (§6.1).
	for _, tool := range []Tool{StateQueryTool(&fakeStateStore{}), StateUpdateTool(&fakeStateStore{})} {
		if tool.Targets != nil {
			t.Errorf("%s declares scope targets; state tools are pure local operations", tool.Name)
		}
		if tool.Destructive || tool.ExploitClass {
			t.Errorf("%s is tagged destructive/exploit-class; state I/O is neither", tool.Name)
		}
		if tool.Lenient {
			t.Errorf("%s is lenient; built-ins are strict", tool.Name)
		}
	}
}

func TestStateToolErrorsSurfaceStoreRefusals(t *testing.T) {
	store := &fakeStateStore{
		queryErr: errors.New("engagementstate: invalid operation: where \"nope\""),
		update:   errors.New("engagementstate: engagement state is locked"),
	}
	if _, err := StateQueryTool(store).Handler(context.Background(), map[string]any{
		"kind": "", "id": "", "where_json": "", "hops": 0, "include_inactive": false, "limit": 0,
	}); err == nil {
		t.Errorf("a store refusal should surface as a tool error")
	}
	if _, err := StateUpdateTool(store).Handler(context.Background(), map[string]any{
		"ops_json": `[{"op":"upsert_entity","kind":"host","addresses":["10.0.0.7"]}]`,
	}); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Errorf("a locked store should surface as a tool error, got %v", err)
	}
}
