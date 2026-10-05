package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/skills"
)

// writeSkill drops a SKILL.md into a skill root under dir/<name>/SKILL.md.
func writeSkill(t *testing.T, root, name, body string) {
	t.Helper()
	sub := filepath.Join(root, name)
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, skills.FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func skillBody(name, description, extra string) string {
	return "---\nname: " + name + "\ndescription: " + description + "\n" + extra + "---\n\n# " + name + "\n\nFollow these steps.\n"
}

func TestBuildDiscoversProjectSkill(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, ".styx", "skills"), "deploy", skillBody("deploy", "ship the app", ""))

	fake := fakemodel.New(fakemodel.WithTurns(
		fakemodel.ToolCalls(fakemodel.Call("c1", "skill", `{"skill":"deploy","reason":"task","args":{}}`)),
		fakemodel.Text("following the deploy workflow"),
	))
	h, err := Build(context.Background(), buildOptions(t, dir, fake))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	if _, ok := h.Tools.Lookup("skill"); !ok {
		t.Fatal("the skill tool was not registered for a model-invocable skill")
	}

	result, err := h.Loop.Run(context.Background(), nil, "deploy this")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	var got string
	for _, m := range result.Messages {
		if m.ToolCallID == "c1" {
			got = m.Content
		}
	}
	if !strings.Contains(got, "Follow these steps.") {
		t.Errorf("skill result = %q, want the project skill's workflow", got)
	}
}

func TestBuildOmitsSkillToolForUserInvokedSkills(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, ".styx", "skills"), "manual",
		skillBody("manual", "human only", "disable-model-invocation: true\n"))

	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()
	if _, ok := h.Tools.Lookup("skill"); ok {
		t.Error("the skill tool was registered with no model-invocable skill")
	}
}

func TestSkillsCommandListsAndInvokes(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, ".styx", "skills"), "deploy", skillBody("deploy", "ship the app", ""))

	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	out, err := h.command("skills", "")
	if err != nil {
		t.Fatalf("/skills = %v", err)
	}
	if !strings.Contains(out, "deploy") || !strings.Contains(out, "model-invocable") {
		t.Errorf("/skills output = %q, want the discovered skill", out)
	}

	// With no submitter, the rendered turn is returned directly.
	out, err = h.command("deploy", "")
	if err != nil {
		t.Fatalf("/deploy = %v", err)
	}
	if !strings.Contains(out, "deploy") {
		t.Errorf("/deploy output = %q, want an invocation turn", out)
	}

	// With a live session, the turn goes to the submitter (via the TUI's
	// guarded path) rather than blocking.
	var submitted []string
	h.setSubmitter(func(text string) { submitted = append(submitted, text) })
	if _, err := h.command("deploy", "prod"); err != nil {
		t.Fatalf("/deploy = %v", err)
	}
	if len(submitted) != 1 || !strings.Contains(submitted[0], "deploy") || !strings.Contains(submitted[0], "prod") {
		t.Errorf("submitted = %v, want one deploy invocation carrying the argument", submitted)
	}
}

func TestBuildRefusesMalformedSkill(t *testing.T) {
	dir := t.TempDir()
	writeSkill(t, filepath.Join(dir, ".styx", "skills"), "broken", "# no frontmatter\n")
	if _, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New())); err == nil {
		t.Fatal("Build() accepted a malformed project SKILL.md")
	}
}

func TestBuildDiscoversGlobalSkill(t *testing.T) {
	global := t.TempDir()
	writeSkill(t, global, "global-only", skillBody("global-only", "from the global root", ""))

	dir := t.TempDir()
	opts := buildOptions(t, dir, fakemodel.New())
	opts.GlobalSkillsDirs = []string{global}
	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v", err)
	}
	defer func() { _ = h.Close() }()

	out, err := h.command("skills", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "global-only") || !strings.Contains(out, "global") {
		t.Errorf("/skills output = %q, want the global skill", out)
	}
}
