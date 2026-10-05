package skills

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the file that defines a skill inside its directory (§8.4).
const FileName = "SKILL.md"

// Source identifies where a skill was discovered.
type Source string

const (
	// SourceGlobal is a skill from a global root (`~/.agents/skills`).
	SourceGlobal Source = "global"
	// SourceProject is a skill from the project root (`.styx/skills`).
	SourceProject Source = "project"
)

// Skill is one discovered agent skill (§8.4): a named workflow. It is data —
// workflow text — never a code plugin, so discovery grants no tools and widens
// no policy.
type Skill struct {
	// Name is the invocation name, from the frontmatter `name` when present,
	// else the directory's basename.
	Name string
	// Description is the frontmatter description: the model-facing pointer for
	// a model-invocable skill, or the human-facing summary for a user-invoked
	// one.
	Description string
	// Body is the workflow content after the frontmatter, returned verbatim as
	// the skill tool's result.
	Body string
	// ModelInvocation reports whether the model may invoke this skill through
	// the skill tool. It is false when the frontmatter sets
	// `disable-model-invocation: true`, which restricts the skill to user
	// invocation only.
	ModelInvocation bool
	// Source is where the skill was found.
	Source Source
	// Path is the SKILL.md file the skill was loaded from.
	Path string
}

// frontmatter is the SKILL.md YAML header (§8.4). Unknown keys are tolerated
// (the format is shared with `~/.agents/skills`), but a malformed value for a
// key the harness reads is refused.
type frontmatter struct {
	Name                   string `yaml:"name"`
	Description            string `yaml:"description"`
	DisableModelInvocation bool   `yaml:"disable-model-invocation"`
}

// Invocation renders the skill as a model-facing turn (§8.4): the workflow
// body, prefixed with the skill's name, plus any supplied arguments echoed
// back. It is text and nothing else — a skill is never a code plugin.
func (s Skill) Invocation(args map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Skill: %s\n\n", s.Name)
	b.WriteString(strings.TrimRight(s.Body, "\n"))
	if len(args) > 0 {
		b.WriteString("\n\nArguments for this invocation:\n")
		if enc, err := json.MarshalIndent(args, "", "  "); err == nil {
			b.Write(enc)
		} else {
			fmt.Fprintf(&b, "%v", args)
		}
	}
	b.WriteString("\n")
	return b.String()
}

// Catalog is an immutable set of discovered skills, keyed by name. Project
// skills shadow global ones on collision (§8.4).
type Catalog struct {
	byName map[string]Skill
}

// Discover loads every skill under each global directory, then the project
// directory. A later definition of a name shadows an earlier one; the project
// directory is last, so a project skill always wins. A missing directory is
// simply empty; a present-but-malformed SKILL.md is an error, never silently
// skipped.
func Discover(globalDirs []string, projectDir string) (*Catalog, error) {
	c := &Catalog{byName: make(map[string]Skill)}
	for _, dir := range globalDirs {
		if err := c.loadDir(dir, SourceGlobal); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(projectDir) != "" {
		if err := c.loadDir(projectDir, SourceProject); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// loadDir loads every immediate subdirectory of dir that contains a SKILL.md.
// A directory without a SKILL.md is not a skill and is skipped.
func (c *Catalog) loadDir(dir string, source Source) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("skills: read %s: %w", dir, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sub := filepath.Join(dir, entry.Name())
		present, err := hasSkillFile(sub)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		sk, err := loadSkill(sub, source)
		if err != nil {
			return err
		}
		c.byName[sk.Name] = sk
	}
	return nil
}

// hasSkillFile reports whether dir holds a regular SKILL.md. A missing file is
// simply "not a skill"; any other stat error is reported rather than silently
// skipping a skill the operator expects to load.
func hasSkillFile(dir string) (bool, error) {
	path := filepath.Join(dir, FileName)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("skills: stat %s: %w", path, err)
	}
	return info.Mode().IsRegular(), nil
}

// loadSkill reads and parses one skill directory.
func loadSkill(dir string, source Source) (Skill, error) {
	path := filepath.Join(dir, FileName)
	//nolint:gosec // skill roots are operator-controlled by design (§8.4).
	data, err := os.ReadFile(path)
	if err != nil {
		return Skill{}, fmt.Errorf("skills: read %s: %w", path, err)
	}
	fm, body, err := parseFrontmatter(string(data))
	if err != nil {
		return Skill{}, fmt.Errorf("skills: %s: %w", path, err)
	}
	name := strings.TrimSpace(fm.Name)
	if name == "" {
		name = filepath.Base(dir)
	}
	if !validName(name) {
		return Skill{}, fmt.Errorf("skills: %s: skill name %q must not be empty or contain whitespace or path separators", path, name)
	}
	return Skill{
		Name:            name,
		Description:     strings.TrimSpace(fm.Description),
		Body:            body,
		ModelInvocation: !fm.DisableModelInvocation,
		Source:          source,
		Path:            path,
	}, nil
}

// parseFrontmatter splits a SKILL.md into its YAML frontmatter and its workflow
// body. The file must open with a `---` line and close the block with one; a
// missing or unterminated block, invalid YAML, or a wrongly-typed value is an
// error.
func parseFrontmatter(content string) (frontmatter, string, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || strings.TrimRight(lines[0], "\r") != "---" {
		return frontmatter{}, "", errors.New("missing frontmatter: SKILL.md must open with a --- line")
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return frontmatter{}, "", errors.New("unterminated frontmatter: no closing --- line")
	}
	var fm frontmatter
	if err := yaml.Unmarshal([]byte(strings.Join(lines[1:end], "\n")), &fm); err != nil {
		return frontmatter{}, "", fmt.Errorf("invalid frontmatter: %w", err)
	}
	body := strings.TrimLeft(strings.Join(lines[end+1:], "\n"), "\n")
	return fm, body, nil
}

// validName rejects a name the user could not type as `/name` or the model
// could not pass in a single string.
func validName(name string) bool {
	if name == "" {
		return false
	}
	return !strings.ContainsAny(name, " \t\n/\\")
}

// Lookup returns the skill with the given name.
func (c *Catalog) Lookup(name string) (Skill, bool) {
	sk, ok := c.byName[name]
	return sk, ok
}

// Skills returns every discovered skill, sorted by name.
func (c *Catalog) Skills() []Skill {
	out := make([]Skill, 0, len(c.byName))
	for _, sk := range c.byName {
		out = append(out, sk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ModelInvocable returns the skills the model may invoke through the skill
// tool, sorted by name. A skill with `disable-model-invocation: true` is
// excluded: it is user-invocable only.
func (c *Catalog) ModelInvocable() []Skill {
	out := make([]Skill, 0, len(c.byName))
	for _, sk := range c.byName {
		if sk.ModelInvocation {
			out = append(out, sk)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProjectDir is the project skill root for a project directory (§10.4).
func ProjectDir(projectDir string) string {
	return filepath.Join(projectDir, ".styx", "skills")
}

// GlobalDirs returns the global skill roots in increasing precedence: the XDG
// data equivalent first, then the canonical `~/.agents/skills`. A name defined
// in more than one root resolves to the later root; the project directory
// always wins over all of them.
func GlobalDirs(env func(string) string) []string {
	if env == nil {
		env = os.Getenv
	}
	home := strings.TrimSpace(env("HOME"))
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	var dirs []string
	if xdg := strings.TrimSpace(env("XDG_DATA_HOME")); xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "agents", "skills"))
	} else if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "agents", "skills"))
	}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".agents", "skills"))
	}
	return dirs
}
