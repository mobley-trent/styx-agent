package repair

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/model"
)

// ErrTurnAborted terminates a turn whose repair budget is spent. It is the
// repair layer's fatal error: the model produced a tool call the harness could
// not fix within the bounded number of structured repairs, so the turn stops
// with a visible error rather than looping (§4.1, §4.4).
var ErrTurnAborted = errors.New("repair: turn aborted")

// Problem is one schema violation, addressed by JSON pointer so the model can
// locate and fix it.
type Problem struct {
	// Path is the JSON-pointer path of the offending value ("" is the root).
	Path string
	// Message describes the violation in model-readable terms.
	Message string
}

// Feedback is the structured error the harness feeds back to the model when a
// tool call's arguments do not match the tool's schema (§3.3, §4.1). It
// carries the call verbatim so the model can see exactly what it emitted.
type Feedback struct {
	// Tool is the invoked tool's name.
	Tool string
	// Raw is the call's arguments string, exactly as emitted.
	Raw string
	// Problems is every violation found, in path order.
	Problems []Problem
}

// Error renders the feedback as the model-facing message. It is deliberately
// explicit about the path and the remedy; a vague error invites another bad
// call, not a repair.
func (f *Feedback) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid arguments for tool %q; fix the arguments and call it again:", f.Tool)
	for _, p := range f.Problems {
		path := p.Path
		if path == "" {
			path = "(root)"
		}
		fmt.Fprintf(&b, "\n  - %s: %s", path, p.Message)
	}
	if f.Raw != "" {
		fmt.Fprintf(&b, "\nreceived: %s", f.Raw)
	}
	return b.String()
}

// Validator validates a tool call's arguments against the schemas of the tools
// exposed for the turn. It is built once per turn from the tool descriptors
// and is safe for concurrent reads.
type Validator struct {
	schemas map[string]map[string]any
	// unparsed holds tools whose declared schema itself could not be parsed.
	// Such a tool fails closed: every call to it is invalid, because the
	// harness cannot know what arguments are legal.
	unparsed map[string]error
}

// NewValidator builds a validator from the turn's tool descriptors. A tool
// whose Parameters are not valid JSON is retained as fail-closed rather than
// silently unvalidated.
func NewValidator(tools []model.Tool) *Validator {
	v := &Validator{
		schemas:  make(map[string]map[string]any, len(tools)),
		unparsed: make(map[string]error),
	}
	for _, t := range tools {
		if len(t.Parameters) == 0 {
			v.unparsed[t.Name] = errors.New("tool declares no parameter schema")
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(t.Parameters, &schema); err != nil {
			v.unparsed[t.Name] = fmt.Errorf("tool schema is not valid JSON: %w", err)
			continue
		}
		v.schemas[t.Name] = schema
	}
	return v
}

// Validate checks one tool call. A nil return means the arguments match the
// tool's schema. A non-nil return is a *Feedback describing every violation.
func (v *Validator) Validate(call model.ToolCall) error {
	schema, ok := v.schemas[call.Name]
	if !ok {
		if parseErr, bad := v.unparsed[call.Name]; bad {
			return &Feedback{Tool: call.Name, Raw: call.Arguments, Problems: []Problem{{
				Message: "the harness cannot validate this tool's arguments: " + parseErr.Error(),
			}}}
		}
		return &Feedback{Tool: call.Name, Raw: call.Arguments, Problems: []Problem{{
			Message: "unknown tool; it is not in this turn's tool set",
		}}}
	}

	value, err := decodeArgs(call.Arguments)
	if err != nil {
		return &Feedback{Tool: call.Name, Raw: call.Arguments, Problems: []Problem{{
			Message: "arguments are not valid JSON: " + err.Error(),
		}}}
	}

	var problems []Problem
	validateValue(schema, value, "", &problems)
	if len(problems) == 0 {
		return nil
	}
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	return &Feedback{Tool: call.Name, Raw: call.Arguments, Problems: problems}
}

// Repairer is the per-turn repair state machine (§4.1): it validates calls and
// allows a bounded number of structured repairs before aborting the turn.
type Repairer struct {
	validator *Validator
	max       int
	used      int
}

// NewRepairer builds a repairer for one turn. max is the number of structured
// repairs permitted before the turn aborts; the spec's bound is 2 (§4.1).
// A max below zero is treated as zero: no repair is ever attempted.
func NewRepairer(v *Validator, maxRepairs int) *Repairer {
	if maxRepairs < 0 {
		maxRepairs = 0
	}
	return &Repairer{validator: v, max: maxRepairs}
}

// Check validates a call and applies the repair budget:
//
//   - valid call                 → nil
//   - invalid, budget remains    → *Feedback (one repair consumed)
//   - invalid, budget exhausted  → error wrapping ErrTurnAborted
//
// The returned error (either kind) is what the harness surfaces; a *Feedback
// is fed back to the model, an ErrTurnAborted aborts the turn visibly.
func (r *Repairer) Check(call model.ToolCall) error {
	err := r.validator.Validate(call)
	if err == nil {
		return nil
	}
	if r.used >= r.max {
		return fmt.Errorf("%w: tool %q still invalid after %d repair(s): %w", ErrTurnAborted, call.Name, r.used, err)
	}
	r.used++
	return err
}

// Used reports how many repairs this turn has consumed.
func (r *Repairer) Used() int { return r.used }

// Remaining reports how many repairs are left this turn.
func (r *Repairer) Remaining() int {
	if r.used >= r.max {
		return 0
	}
	return r.max - r.used
}

// decodeArgs decodes a tool call's arguments into a JSON value. An empty
// argument string is the empty object, matching the provider's convention for
// a call with no parameters.
func decodeArgs(raw string) (any, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}, nil
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	// Anything after the first value but EOF means the arguments are not a
	// single JSON value.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("arguments contain more than one JSON value")
		}
		return nil, err
	}
	return value, nil
}

// validateValue checks a decoded JSON value against a schema, appending every
// violation. It supports the subset of JSON Schema the harness's tools use:
// type (including type unions), required, properties, additionalProperties,
// items, and enum. Unknown keywords are ignored rather than guessed at.
func validateValue(schema map[string]any, value any, path string, problems *[]Problem) {
	if schema == nil {
		return
	}

	if want, ok := schema["type"]; ok {
		if !matchesType(want, value) {
			*problems = append(*problems, Problem{
				Path:    path,
				Message: fmt.Sprintf("expected %s, got %s", typeName(want), jsonTypeName(value)),
			})
			// A type mismatch makes deeper checks meaningless.
			return
		}
	}

	if enum, ok := schema["enum"].([]any); ok && !inEnum(enum, value) {
		*problems = append(*problems, Problem{
			Path:    path,
			Message: fmt.Sprintf("value %s is not one of the allowed values", compactJSON(value)),
		})
	}

	switch v := value.(type) {
	case map[string]any:
		validateObject(schema, v, path, problems)
	case []any:
		validateArray(schema, v, path, problems)
	}
}

func validateObject(schema map[string]any, obj map[string]any, path string, problems *[]Problem) {
	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			key, isString := name.(string)
			if !isString {
				continue
			}
			if _, present := obj[key]; !present {
				*problems = append(*problems, Problem{
					Path:    path + "/" + key,
					Message: "required property is missing",
				})
			}
		}
	}

	props, _ := schema["properties"].(map[string]any)
	for key, sub := range props {
		subSchema, ok := sub.(map[string]any)
		if !ok {
			continue
		}
		if child, present := obj[key]; present {
			validateValue(subSchema, child, path+"/"+key, problems)
		}
	}

	if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
		for key := range obj {
			if _, declared := props[key]; !declared {
				*problems = append(*problems, Problem{
					Path:    path + "/" + key,
					Message: "unexpected property (additional properties are not allowed)",
				})
			}
		}
	}
}

func validateArray(schema map[string]any, arr []any, path string, problems *[]Problem) {
	items, ok := schema["items"].(map[string]any)
	if !ok {
		return
	}
	for i, elem := range arr {
		validateValue(items, elem, fmt.Sprintf("%s/%d", path, i), problems)
	}
}

// matchesType reports whether a value satisfies a schema "type", which may be
// a single name or a list of alternatives.
func matchesType(want any, value any) bool {
	switch w := want.(type) {
	case string:
		return matchesTypeName(w, value)
	case []any:
		for _, alt := range w {
			if name, ok := alt.(string); ok && matchesTypeName(name, value) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func matchesTypeName(name string, value any) bool {
	switch name {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		return isJSONNumber(value)
	case "integer":
		n, ok := numberValue(value)
		return ok && n == float64(int64(n))
	case "null":
		return value == nil
	default:
		return true
	}
}

func isJSONNumber(value any) bool {
	switch value.(type) {
	case json.Number, float64, int, int64:
		return true
	default:
		return false
	}
}

func numberValue(value any) (float64, bool) {
	switch n := value.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func inEnum(enum []any, value any) bool {
	for _, allowed := range enum {
		if sameJSON(allowed, value) {
			return true
		}
	}
	return false
}

// sameJSON compares JSON values structurally, treating numbers by value.
func sameJSON(a, b any) bool {
	if af, ok := numberValue(a); ok {
		if bf, ok := numberValue(b); ok {
			return af == bf
		}
		return false
	}
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ab) == string(bb)
}

func typeName(want any) string {
	switch w := want.(type) {
	case string:
		return w
	case []any:
		parts := make([]string, 0, len(w))
		for _, alt := range w {
			if name, ok := alt.(string); ok {
				parts = append(parts, name)
			}
		}
		return strings.Join(parts, " or ")
	default:
		return "value"
	}
}

func jsonTypeName(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		if isJSONNumber(value) {
			return "number"
		}
		return "value"
	}
}

// compactJSON renders a JSON value inline for an error message, falling back
// to a placeholder when it cannot be marshaled.
func compactJSON(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		return "?"
	}
	return string(b)
}
