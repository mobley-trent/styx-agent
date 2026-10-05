package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSkill drops a SKILL.md under dir/<name>/SKILL.md.
func writeSkill(t *testing.T, dir, name, body string) string {
	t.Helper()
	sub := filepath.Join(dir, name)
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, FileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func skillMD(name, description string, extra string) string {
	return "---\nname: " + name + "\ndescription: " + description + "\n" + extra + "---\n\n# " + name + "\n\nDo the thing.\n"
}

func TestDiscoverMergesGlobalAndProject(t *testing.T) {
	global := t.TempDir()
	project := t.TempDir()
	writeSkill(t, global, "alpha", skillMD("alpha", "global alpha", ""))
	writeSkill(t, project, "beta", skillMD("beta", "project beta", ""))

	catalog, err := Discover([]string{global}, project)
	if err != nil {
		t.Fatalf("Discover() = %v", err)
	}
	if got := len(catalog.Skills()); got != 2 {
		t.Fatalf("len(Skills()) = %d, want 2", got)
	}
	for _, name := range []string{"alpha", "beta"} {
		sk, ok := catalog.Lookup(name)
		if !ok {
			t.Fatalf("skill %q not discovered", name)
		}
		if !strings.Contains(sk.Body, "Do the thing.") {
			t.Errorf("skill %q body = %q, want the workflow text", name, sk.Body)
		}
	}
	if sk, _ := catalog.Lookup("alpha"); sk.Source != SourceGlobal {
		t.Errorf("alpha source = %q, want global", sk.Source)
	}
	if sk, _ := catalog.Lookup("beta"); sk.Source != SourceProject {
		t.Errorf("beta source = %q, want project", sk.Source)
	}
}

func TestProjectShadowsGlobalOnNameCollision(t *testing.T) {
	global := t.TempDir()
	project := t.TempDir()
	writeSkill(t, global, "shared", skillMD("shared", "from global", ""))
	writeSkill(t, project, "shared", skillMD("shared", "from project", ""))

	catalog, err := Discover([]string{global}, project)
	if err != nil {
		t.Fatalf("Discover() = %v", err)
	}
	if got := len(catalog.Skills()); got != 1 {
		t.Fatalf("len(Skills()) = %d, want 1 (shadowed, not duplicated)", got)
	}
	sk, ok := catalog.Lookup("shared")
	if !ok {
		t.Fatal("shared skill not discovered")
	}
	if sk.Source != SourceProject || sk.Description != "from project" {
		t.Errorf("shadowed skill = %+v, want the project copy", sk)
	}
}

func TestMalformedFrontmatterRefused(t *testing.T) {
	cases := map[string]string{
		"no opening delimiter": "# just markdown\n",
		"unterminated":         "---\nname: x\n",
		"invalid yaml":         "---\nname: [oops\ndescription: x\n---\nbody\n",
		"wrong type":           "---\nname: x\ndisable-model-invocation: notabool\n---\nbody\n",
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			global := t.TempDir()
			writeSkill(t, global, "broken", body)
			if _, err := Discover([]string{global}, ""); err == nil {
				t.Fatal("Discover() accepted a malformed SKILL.md")
			}
		})
	}
}

func TestModelInvocationMetadata(t *testing.T) {
	global := t.TempDir()
	writeSkill(t, global, "auto", skillMD("auto", "model may invoke", ""))
	writeSkill(t, global, "manual", skillMD("manual", "human only", "disable-model-invocation: true\n"))

	catalog, err := Discover([]string{global}, "")
	if err != nil {
		t.Fatalf("Discover() = %v", err)
	}
	sk, _ := catalog.Lookup("auto")
	if !sk.ModelInvocation {
		t.Error("auto skill is not model-invocable")
	}
	sk, _ = catalog.Lookup("manual")
	if sk.ModelInvocation {
		t.Error("manual skill is model-invocable despite disable-model-invocation")
	}
	if got := catalog.ModelInvocable(); len(got) != 1 || got[0].Name != "auto" {
		t.Errorf("ModelInvocable() = %+v, want just auto", got)
	}
}

func TestInvocationRendersWorkflowAndArgs(t *testing.T) {
	sk := Skill{Name: "deploy", Body: "Step one.\nStep two.\n"}
	got := sk.Invocation(map[string]any{"env": "prod"})
	for _, want := range []string{"# Skill: deploy", "Step one.", "Step two.", `"env": "prod"`} {
		if !strings.Contains(got, want) {
			t.Errorf("Invocation() is missing %q:\n%s", want, got)
		}
	}
	if bare := sk.Invocation(nil); strings.Contains(bare, "Arguments") {
		t.Errorf("Invocation(nil) echoed arguments:\n%s", bare)
	}
}

func TestUnknownAndEmptyDirs(t *testing.T) {
	catalog, err := Discover([]string{filepath.Join(t.TempDir(), "nope")}, "")
	if err != nil {
		t.Fatalf("Discover() over a missing dir = %v, want nil", err)
	}
	if len(catalog.Skills()) != 0 {
		t.Errorf("Skills() = %+v, want empty", catalog.Skills())
	}
	if _, ok := catalog.Lookup("absent"); ok {
		t.Error("Lookup found a skill in an empty catalog")
	}
}

func TestGlobalDirsHonorXDGAndHome(t *testing.T) {
	env := map[string]string{"HOME": "/home/op", "XDG_DATA_HOME": "/xdg/data"}
	got := GlobalDirs(func(k string) string { return env[k] })
	want := []string{
		filepath.Join("/xdg", "data", "agents", "skills"),
		filepath.Join("/home/op", ".agents", "skills"),
	}
	if len(got) != len(want) {
		t.Fatalf("GlobalDirs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("GlobalDirs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// With no XDG_DATA_HOME the data equivalent falls back under $HOME.
	got = GlobalDirs(func(k string) string {
		if k == "HOME" {
			return "/home/op"
		}
		return ""
	})
	if got[0] != filepath.Join("/home/op", ".local", "share", "agents", "skills") {
		t.Errorf("fallback data dir = %q", got[0])
	}
}

func TestProjectDir(t *testing.T) {
	got := ProjectDir("/work/repo")
	if got != filepath.Join("/work/repo", ".styx", "skills") {
		t.Errorf("ProjectDir() = %q", got)
	}
}
