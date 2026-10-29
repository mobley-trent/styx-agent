package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// Names of the engagement-state tools (§5.1).
const (
	// StateQueryToolName reads engagement state.
	StateQueryToolName = "state_query"
	// StateUpdateToolName writes engagement state through typed ops.
	StateUpdateToolName = "state_update"
)

// StateStore is the engagement-state seam these tools read and write through
// (§6 of docs/engagement-state.md). `agent` knows only this shape: the
// concrete store lives in internal/engagementstate, and a test substitutes a
// fake.
type StateStore interface {
	// Query answers a structured read: filters, listing, and 1–2-hop
	// neighborhood reads over the relationship graph.
	Query(q engagementstate.Query) (engagementstate.Snapshot, error)
	// Update applies one batch of typed ops atomically, stamped with the
	// harness's provenance.
	Update(ctx context.Context, origin engagementstate.Origin, ops []engagementstate.Op) (engagementstate.Receipt, error)
	// Snapshot returns the whole record as the read shape, complete and never
	// truncated: the attack-path computation reasons over all of it.
	Snapshot() engagementstate.Snapshot
}

// originKey carries a tool call's origin down to the handlers that mutate
// engagement state: the loop stamps the subagent role, so provenance is the
// harness's, never the model's.
type originKey struct{}

// withOrigin stamps a tool call's provenance origin onto its context. The loop
// calls it for every dispatch, so a state write inside a subagent is
// attributable to that run.
func withOrigin(ctx context.Context, subagent string) context.Context {
	if subagent == "" {
		return ctx
	}
	return context.WithValue(ctx, originKey{}, subagent)
}

// subagentOrigin reads the origin a loop stamped on the context.
func subagentOrigin(ctx context.Context) string {
	subagent, _ := ctx.Value(originKey{}).(string)
	return subagent
}

// stateQuerySchema is the `state_query` descriptor's JSON Schema. Strict mode
// declares every property and requires all of them, so an unused filter travels
// as the empty value: "" for strings, 0 for numbers, false for booleans.
const stateQuerySchema = `{
  "type": "object",
  "properties": {
    "kind": {
      "type": "string",
      "description": "Entity kind to list: host, service, credential, access, segment, or finding. Empty lists every kind."
    },
    "id": {
      "type": "string",
      "description": "Read exactly one record by its harness id (\"host-1a2b\"). Empty selects by kind and where_json instead."
    },
    "where_json": {
      "type": "string",
      "description": "A JSON object of attribute-equality filters, e.g. {\"state\":\"open\",\"port\":\"445\"}. Empty applies none. Keys: id, kind, active, address, hostname, os, host, port, proto, product, version, state, type, principal, target, level, via, tag, label, cidr, title, severity, status, confidence, verification, evidence, source, session. An unknown key is refused."
    },
    "hops": {
      "type": "integer",
      "description": "Graph hops to expand around the selection: 0 (the selection only), 1, or 2. Edges are followed in both directions."
    },
    "include_inactive": {
      "type": "boolean",
      "description": "Include deactivated records, which a listing hides by default."
    },
    "limit": {
      "type": "integer",
      "description": "Cap on records returned. 0 uses the default of 200; the maximum is 1000."
    }
  },
  "required": ["kind", "id", "where_json", "hops", "include_inactive", "limit"],
  "additionalProperties": false
}`

// stateUpdateSchema is the `state_update` descriptor's JSON Schema. The op
// batch travels as a JSON string because strict mode cannot express a
// free-form array of heterogeneous objects; the store decodes it strictly, so
// an unknown op field is refused rather than ignored.
const stateUpdateSchema = `{
  "type": "object",
  "properties": {
    "ops_json": {
      "type": "string",
      "description": "A JSON array of typed operations, applied as one atomic batch: either every op lands or none does. The harness stamps provenance (writing tool, session, time) — supplying source, session, or time is refused.\n- {\"op\":\"upsert_entity\",\"kind\":\"host\",\"addresses\":[\"10.0.0.7\"],\"hostname\":\"web01\",\"os\":\"linux\",\"tags\":[\"dmz\"]}\n- {\"op\":\"upsert_entity\",\"kind\":\"service\",\"host\":\"host-1a2b\",\"port\":445,\"proto\":\"tcp\",\"product\":\"smb\",\"version\":\"3.1.1\",\"state\":\"open\"}\n- {\"op\":\"upsert_entity\",\"kind\":\"credential\",\"type\":\"password\",\"principal\":\"ACME\\\\admin\",\"secret\":\"...\"}\n- {\"op\":\"upsert_entity\",\"kind\":\"access\",\"principal\":\"credential-1a2b or an account name\",\"target\":\"host-1a2b\",\"level\":\"user\",\"via\":\"finding-1a2b\"}\n- {\"op\":\"upsert_entity\",\"kind\":\"segment\",\"label\":\"dmz\",\"cidrs\":[\"10.0.0.0/24\"]}\n- {\"op\":\"upsert_finding\",\"title\":\"SMB signing disabled\",\"severity\":\"medium\",\"confidence\":\"high\",\"affected\":[\"host-1a2b\"],\"cvss_vector\":\"...\"}\n- {\"op\":\"attach_evidence\",\"finding\":\"finding-1a2b\",\"evidence_kind\":\"cli-output\",\"ref\":\"path or excerpt\"}\n- {\"op\":\"set_status\",\"finding\":\"finding-1a2b\",\"status\":\"confirmed\"}\n- {\"op\":\"set_verification\",\"finding\":\"finding-1a2b\",\"verification\":\"verified\"}\n- {\"op\":\"add_edge\",\"type\":\"RUNS_ON\",\"from\":\"service-1a2b\",\"to\":\"host-3c4d\",\"confidence\":\"high\"}\n- {\"op\":\"remove_edge\",\"type\":\"RUNS_ON\",\"from\":\"service-1a2b\",\"to\":\"host-3c4d\"}\nSeverities: info, low, medium, high, critical. Evidence kinds: cli-output, http-response, artifact, screenshot, note. Statuses: detected, confirmed, false_positive, fixed, risk_accepted. Edge types: RESOLVES_TO, RUNS_ON, IN_SEGMENT, CREDENTIAL_FROM, VALID_FOR, ADMIN_OF, PIVOT_TO, EXPLOITED_VIA. References must resolve to records the store already holds (an address or hostname resolves to its host); upsert the host before the service that names it, in the same batch. A new finding starts detected and unverified, a status only moves along its lifecycle, and verified or refuted requires at least one evidence item."
    }
  },
  "required": ["ops_json"],
  "additionalProperties": false
}`

// StateQueryTool is the §5.1 `state_query` tool: reads over engagement state.
// It carries no scope targets — a read of the local record is not a network
// call — so it is a rule-table matter alone (§6.1): the default table denies it
// in safe mode (there is no store to read) and allows it, audited, in
// engagement mode.
func StateQueryTool(store StateStore) Tool {
	return Tool{
		Name:        StateQueryToolName,
		Description: "Read engagement state: hosts, services, credentials, access, segments, findings, and the relationship graph. Filter by kind and attribute, read one record by id, or expand a neighborhood over the graph. Credential secrets are never returned.",
		Parameters:  json.RawMessage(stateQuerySchema),
		Handler: func(_ context.Context, args map[string]any) (string, error) {
			if store == nil {
				return "", errors.New("no engagement state is available: state_query needs an active engagement")
			}
			query, err := parseStateQuery(args)
			if err != nil {
				return "", err
			}
			snapshot, err := store.Query(query)
			if err != nil {
				return "", err
			}
			return snapshot.Text(), nil
		},
	}
}

// StateUpdateTool is the §5.1 `state_update` tool: typed writes over
// engagement state. Writes are local and non-scope, so the default table
// allows them in engagement mode rather than prompting per write — the audit
// trail is the control (§7 of docs/engagement-state.md).
func StateUpdateTool(store StateStore) Tool {
	return Tool{
		Name:        StateUpdateToolName,
		Description: "Write engagement state through typed operations: upsert entities and findings, attach evidence, move a finding's status or verification, and add or remove graph edges. One call is one atomic batch. Provenance is harness-stamped.",
		Parameters:  json.RawMessage(stateUpdateSchema),
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			if store == nil {
				return "", errors.New("no engagement state is available: state_update needs an active engagement")
			}
			raw, err := stringArg(args, "ops_json")
			if err != nil {
				return "", err
			}
			ops, err := engagementstate.DecodeOps(raw)
			if err != nil {
				return "", err
			}
			origin := engagementstate.Origin{Tool: StateUpdateToolName, Subagent: subagentOrigin(ctx)}
			receipt, err := store.Update(ctx, origin, ops)
			if err != nil {
				return "", err
			}
			encoded, err := json.Marshal(receipt)
			if err != nil {
				return "", fmt.Errorf("state_update: encode receipt: %w", err)
			}
			return string(encoded), nil
		},
	}
}

// parseStateQuery reads a state_query call's arguments.
func parseStateQuery(args map[string]any) (engagementstate.Query, error) {
	rawKind, err := stringArg(args, "kind")
	if err != nil {
		return engagementstate.Query{}, err
	}
	id, err := stringArg(args, "id")
	if err != nil {
		return engagementstate.Query{}, err
	}
	rawWhere, err := stringArg(args, "where_json")
	if err != nil {
		return engagementstate.Query{}, err
	}
	hops, err := intArg(args, "hops", 0, 2)
	if err != nil {
		return engagementstate.Query{}, err
	}
	includeInactive, err := boolArg(args, "include_inactive")
	if err != nil {
		return engagementstate.Query{}, err
	}
	limit, err := intArg(args, "limit", 0, 1000)
	if err != nil {
		return engagementstate.Query{}, err
	}
	where, err := parseWhere(rawWhere)
	if err != nil {
		return engagementstate.Query{}, err
	}

	query := engagementstate.Query{
		Kind:            engagementstate.Kind(rawKind),
		ID:              id,
		Where:           where,
		Hops:            hops,
		IncludeInactive: includeInactive,
		Limit:           limit,
	}
	if query.Kind == "" && query.ID == "" && hops > 0 {
		// Hops expand a selection; with no selection there is nothing to
		// expand, and a silently ignored parameter would look like it worked.
		return engagementstate.Query{}, errors.New("state_query: hops needs a selection: name an id, a kind, or where_json")
	}
	return query, nil
}

// parseWhere decodes a `where_json` filter object. Values must be strings: the
// filter vocabulary compares text, and a nested value could only be a silent
// mismatch.
func parseWhere(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("where_json: want a JSON object of attribute filters: %w", err)
	}
	where := make(map[string]string, len(decoded))
	for key, value := range decoded {
		switch v := value.(type) {
		case string:
			where[key] = v
		case float64:
			where[key] = trimFloat(v)
		case bool:
			where[key] = fmt.Sprint(v)
		default:
			return nil, fmt.Errorf("where_json: %q: want a string, number, or boolean value", key)
		}
	}
	return where, nil
}

// trimFloat renders a JSON number without a trailing ".0", so {"port":445} and
// {"port":"445"} filter identically.
func trimFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprint(int64(v))
	}
	return fmt.Sprint(v)
}
