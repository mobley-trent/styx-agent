package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/skills"
)

// skillCatalog builds a catalog from an in-memory set of SKILL.md files. Each
// entry's name is its directory slug.
func skillCatalog(t *testing.T, files map[string]string) *skills.Catalog {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		sub := filepath.Join(dir, name)
		if err := os.MkdirAll(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, skills.FileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := skills.Discover([]string{dir}, "")
	if err != nil {
		t.Fatalf("Discover() = %v", err)
	}
	return catalog
}

func skillDoc(name, description, extra string) string {
	return "---\nname: " + name + "\ndescription: " + description + "\n" + extra + "---\n\nStep one.\nStep two.\n"
}

func TestSkillToolReturnsWorkflowText(t *testing.T) {
	catalog := skillCatalog(t, map[string]string{
		"deploy": skillDoc("deploy", "ship it", ""),
	})
	tool, ok := SkillTool(catalog)
	if !ok {
		t.Fatal("SkillTool() = false, want the tool for a model-invocable skill")
	}
	if tool.Name != SkillToolName {
		t.Fatalf("tool name = %q, want %q", tool.Name, SkillToolName)
	}
	if !strings.Contains(tool.Description, "deploy: ship it") {
		t.Errorf("description does not advertise the skill:\n%s", tool.Description)
	}

	got, err := tool.Handler(context.Background(), map[string]any{
		"skill": "deploy", "reason": "asked", "args": map[string]any{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	for _, want := range []string{"# Skill: deploy", "Step one.", "Step two.", `"env": "prod"`} {
		if !strings.Contains(got, want) {
			t.Errorf("result is missing %q:\n%s", want, got)
		}
	}
}

func TestSkillToolRefusesUserInvokedSkill(t *testing.T) {
	catalog := skillCatalog(t, map[string]string{
		"auto":   skillDoc("auto", "model may invoke", ""),
		"manual": skillDoc("manual", "human only", "disable-model-invocation: true\n"),
	})
	tool, ok := SkillTool(catalog)
	if !ok {
		t.Fatal("SkillTool() = false, want the tool because auto is model-invocable")
	}
	if strings.Contains(tool.Description, "- manual") {
		t.Errorf("description advertises a user-invoked skill:\n%s", tool.Description)
	}
	if _, err := tool.Handler(context.Background(), map[string]any{"skill": "manual", "reason": "x", "args": map[string]any{}}); err == nil {
		t.Fatal("Handler() allowed the model to invoke a user-invoked skill")
	}
	if _, err := tool.Handler(context.Background(), map[string]any{"skill": "nope", "reason": "x", "args": map[string]any{}}); err == nil {
		t.Fatal("Handler() accepted an unknown skill")
	}
}

func TestSkillToolAbsentWhenNoneModelInvocable(t *testing.T) {
	catalog := skillCatalog(t, map[string]string{
		"manual": skillDoc("manual", "human only", "disable-model-invocation: true\n"),
	})
	if _, ok := SkillTool(catalog); ok {
		t.Error("SkillTool() = true, want no tool when nothing is model-invocable")
	}
	if _, ok := SkillTool(nil); ok {
		t.Error("SkillTool(nil) = true, want no tool")
	}
}

func TestSkillToolSchemaIsStrictCompliant(t *testing.T) {
	catalog := skillCatalog(t, map[string]string{"deploy": skillDoc("deploy", "ship it", "")})
	tool, ok := SkillTool(catalog)
	if !ok {
		t.Fatal("SkillTool() = false")
	}
	var schema map[string]any
	if err := json.Unmarshal(tool.Parameters, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	checkStrictObject(t, tool.Name, schema)
}

// TestSkillCannotAddToolsOrAlterVerdicts is the policy-invariant test (§8.4):
// invoking a skill returns workflow text and must not enlarge the tool set or
// change the verdict a later guarded call receives. The skill tool is an
// ordinary tool on the same choke point as everything else.
func TestSkillCannotAddToolsOrAlterVerdicts(t *testing.T) {
	dir := workspace(t, map[string]string{"a.txt": "one\n"})
	catalog := skillCatalog(t, map[string]string{
		"deploy": skillDoc("deploy", "ship it", ""),
	})
	skillTool, ok := SkillTool(catalog)
	if !ok {
		t.Fatal("SkillTool() = false")
	}

	// The base registry already contains the guarded write tool.
	write := WriteFileTool(dir)
	base := mustRegistry(t, skillTool, write)
	before := base.Names()

	var auditBuf bytes.Buffer
	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(
			fakemodel.ToolCalls(fakemodel.Call("c1", SkillToolName, `{"skill":"deploy","reason":"task","args":{}}`)),
			fakemodel.ToolCalls(callWrite("a.txt", "changed\n")),
			fakemodel.Text("done"),
		)),
		base, mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&auditBuf), testSystemPrompt,
		// No interactive prompter: a guarded write defaults to deny.
	)
	result, err := loop.Run(context.Background(), nil, "run the deploy skill")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}

	// The skill returned its workflow text to the model.
	var skillResult string
	for _, m := range result.Messages {
		if m.ToolCallID == "c1" {
			skillResult = m.Content
		}
	}
	if !strings.Contains(skillResult, "Step one.") {
		t.Errorf("skill result = %q, want the workflow text", skillResult)
	}

	// The write that followed was denied, not widened, by the skill.
	records := auditRecords(t, &auditBuf)
	if len(records) != 2 {
		t.Fatalf("audit records = %+v, want the skill call and the write", records)
	}
	if records[1].Tool != write.Name || records[1].Verdict != audit.VerdictDeny {
		t.Errorf("write verdict = %+v, want deny (the skill widened nothing)", records[1])
	}
	if onDisk := readWorkspace(t, filepath.Join(dir, "a.txt")); onDisk != "one\n" {
		t.Errorf("file = %q, want it untouched by the denied write", onDisk)
	}

	// The skill tool itself added no descriptor to the registry.
	if got := base.Names(); !slices.Equal(got, before) {
		t.Errorf("registry names = %v, want unchanged %v", got, before)
	}
}
