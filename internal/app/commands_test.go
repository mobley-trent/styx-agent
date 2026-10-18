package app

import (
	"context"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/tui"
)

// commandInfo resolves one registry entry as the TUI sees it.
func commandInfo(t *testing.T, h *Harness, name string) tui.CommandInfo {
	t.Helper()
	for _, info := range h.commandInfos() {
		if info.Name == name {
			return info
		}
	}
	t.Fatalf("no registry entry for %q", name)
	return tui.CommandInfo{}
}

// The registry is the single source of the command surface: dispatch, /help,
// the slash menu, and the pickers all come from it (docs/tui-parity.md §4).
func TestCommandRegistryIsTheSingleSource(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	help, err := h.command("help", "")
	if err != nil {
		t.Fatalf("help = %v, want nil", err)
	}
	registry := commandRegistry()
	infos := h.commandInfos()
	if len(infos) != len(registry) {
		t.Fatalf("commandInfos has %d entries, want the registry's %d", len(infos), len(registry))
	}
	for _, info := range infos {
		if !strings.Contains(help, info.Usage) {
			t.Errorf("help text is missing %q:\n%s", info.Usage, help)
		}
		if !strings.Contains(help, info.Description) {
			t.Errorf("help text is missing the description of %q:\n%s", info.Name, help)
		}
	}

	// Aliases dispatch to the same command but never appear in the menu.
	if out, err := h.command("h", ""); err != nil || out != help {
		t.Errorf("h = %q, %v, want the help text", out, err)
	}
	if out, err := h.command("packs", ""); err != nil || out == "" {
		t.Errorf("packs = %q, %v, want the pack listing", out, err)
	}
	for _, info := range infos {
		if info.Name == "packs" || info.Name == "exit" {
			t.Errorf("alias %q is listed in the menu", info.Name)
		}
	}
	if _, err := h.command("bogus", ""); err == nil {
		t.Error("an unregistered command was accepted")
	}
}

// The commands that declare options serve the picker's rows.
func TestCommandPickerOptions(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	pickers := 0
	for _, info := range h.commandInfos() {
		if info.Options == nil {
			if info.Name == "model" || info.Name == "resume" || info.Name == "theme" {
				t.Errorf("%s declares no picker options", info.Name)
			}
			continue
		}
		pickers++
	}
	if pickers != 3 {
		t.Errorf("%d commands declare pickers, want model, resume, and theme", pickers)
	}

	opts := commandInfo(t, h, "model").Options()
	if len(opts) != len(h.Config.Models) {
		t.Fatalf("model picker lists %d entries, want the %d pinned models", len(opts), len(h.Config.Models))
	}
	current := h.currentModel()
	for i, opt := range opts {
		if opt.Value != h.Config.Models[i].ID {
			t.Errorf("model option %d = %q, want %q", i, opt.Value, h.Config.Models[i].ID)
		}
		if !strings.Contains(opt.Detail, "token window") {
			t.Errorf("model option %d detail = %q, want the context window", i, opt.Detail)
		}
		if marked := strings.Contains(opt.Label, "(current)"); marked != (opt.Value == current) {
			t.Errorf("model option %d label = %q, want only the model in force marked", i, opt.Label)
		}
	}

	// A fresh project has no sessions to resume, so /resume's picker is empty
	// and the TUI falls back to the command's own listing.
	if got := commandInfo(t, h, "resume").Options(); len(got) != 0 {
		t.Errorf("resume picker lists %v, want none on a project with no sessions", got)
	}

	themeOpts := commandInfo(t, h, "theme").Options()
	if len(themeOpts) != 3 {
		t.Fatalf("theme picker lists %d entries, want dark, light, and auto", len(themeOpts))
	}
	if !strings.Contains(themeOpts[2].Label, "(current)") {
		t.Errorf("theme option %q = %q, want auto marked while no choice is set", themeOpts[2].Value, themeOpts[2].Label)
	}
}

// /theme reports and records the operator's color scheme; auto hands the choice
// back to the terminal (§9.6).
func TestThemeCommand(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	if got := h.themePreference(); got != "" {
		t.Fatalf("default theme preference = %q, want auto (empty)", got)
	}
	if out, err := h.command("theme", ""); err != nil || !strings.Contains(out, "auto") {
		t.Errorf("theme = %q, %v, want the auto readout", out, err)
	}

	out, err := h.command("theme", "light")
	if err != nil || !strings.Contains(out, "light") {
		t.Fatalf("theme light = %q, %v", out, err)
	}
	if got := h.themePreference(); got != "light" {
		t.Errorf("theme preference = %q, want light", got)
	}

	if _, err := h.command("theme", "neon"); err == nil {
		t.Error("an unknown theme was accepted")
	}
	if got := h.themePreference(); got != "light" {
		t.Errorf("theme preference = %q, want the refusal to leave it alone", got)
	}

	if _, err := h.command("theme", "auto"); err != nil {
		t.Fatalf("theme auto = %v", err)
	}
	if got := h.themePreference(); got != "" {
		t.Errorf("theme preference = %q, want auto to clear the override", got)
	}
}

// Every registry entry is complete enough for all three doors: a usage line for
// help, a description for the menu, and a handler for dispatch.
func TestCommandSurfaceAgreesAcrossDoors(t *testing.T) {
	dir := t.TempDir()
	h, err := Build(context.Background(), buildOptions(t, dir, fakemodel.New()))
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	help, _ := h.command("help", "")
	if listed, want := strings.Count(help, "\n  /"), len(commandRegistry()); listed != want {
		t.Errorf("help lists %d commands, want the registry's %d:\n%s", listed, want, help)
	}
	for _, spec := range commandRegistry() {
		if spec.usage == "" || spec.desc == "" || spec.run == nil {
			t.Errorf("registry entry %q is incomplete: %+v", spec.name, spec)
		}
		if !strings.HasPrefix(spec.usage, "/"+spec.name) {
			t.Errorf("registry entry %q has usage %q", spec.name, spec.usage)
		}
	}
}
