package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	_ "embed"
)

// ToolsetPath is where a session image declares what it carries
// (docs/sandbox-image.md §9). It is read once, after the container starts, and
// never probed.
const ToolsetPath = "/etc/styx/toolset.json"

// ToolsetSchemaVersion is the only manifest contract this build knows. An image
// declaring another version is refused rather than described by guesswork
// (§4.4).
const ToolsetSchemaVersion = 1

// Toolset is an image's declaration of the scanners it carries and the parser
// tools that read their output (§9).
type Toolset struct {
	SchemaVersion int        `json:"schema_version"`
	ImageVersion  string     `json:"image_version"`
	Base          string     `json:"base"`
	Tools         []Tool     `json:"tools"`
	Wordlists     []Wordlist `json:"wordlists"`
	// Data records the tool data baked into the image, so staleness is legible
	// rather than assumed away (§8).
	Data Data `json:"data"`
}

// Data is the baked tool data's provenance: the versions whose age is the
// image's age.
type Data struct {
	NucleiTemplates string `json:"nuclei_templates"`
	SemgrepRules    string `json:"semgrep_rules"`
	TrivyDB         string `json:"trivy_db"`
	TrivyJavaDB     string `json:"trivy_java_db"`
	Seclists        string `json:"seclists"`
}

// complete reports whether every baked-data provenance field is declared.
func (d Data) complete() bool {
	return d.NucleiTemplates != "" && d.SemgrepRules != "" && d.TrivyDB != "" && d.TrivyJavaDB != "" && d.Seclists != ""
}

// Tool is one declared scanner. A nil Parser is a tool the model parses
// itself, which is stated in the prompt rather than left ambiguous (§2.1).
type Tool struct {
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Parser  *string `json:"parser"`
}

// Wordlist is one baked wordlist, checksummed so the declaration can be
// checked against the bytes (§2.2).
type Wordlist struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// knownParsers is the closed set of parser tools a manifest may name. The set
// is the harness's, not the image's: an image cannot invent a parser tool by
// declaring one.
var knownParsers = map[string]bool{
	"nmap_parse":       true,
	"nuclei_parse":     true,
	"sqlmap_parse":     true,
	"gobuster_parse":   true,
	"cme_parse":        true,
	"bloodhound_parse": true,
}

// ParseToolset strictly parses and validates a toolset manifest. Unknown
// fields, a schema version this build does not know, an empty tool list, or a
// parser tool outside the closed set are all errors: a manifest styx cannot
// describe truthfully is not one it will run behind.
func ParseToolset(data []byte) (Toolset, error) {
	var t Toolset
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Toolset{}, fmt.Errorf("toolset manifest: %w", err)
	}
	if dec.More() {
		return Toolset{}, fmt.Errorf("toolset manifest: trailing data after the document")
	}
	if t.SchemaVersion != ToolsetSchemaVersion {
		return Toolset{}, fmt.Errorf("toolset manifest: schema version %d is not one this build knows (want %d)", t.SchemaVersion, ToolsetSchemaVersion)
	}
	if strings.TrimSpace(t.ImageVersion) == "" {
		return Toolset{}, fmt.Errorf("toolset manifest: image_version is required")
	}
	if !strings.Contains(t.Base, "@sha256:") {
		return Toolset{}, fmt.Errorf("toolset manifest: base %q is not pinned by digest", t.Base)
	}
	if len(t.Tools) == 0 {
		return Toolset{}, fmt.Errorf("toolset manifest: tools is empty")
	}
	for i, tool := range t.Tools {
		if strings.TrimSpace(tool.Name) == "" || strings.TrimSpace(tool.Version) == "" {
			return Toolset{}, fmt.Errorf("toolset manifest: tools[%d] needs a name and a version", i)
		}
		if tool.Parser != nil && !knownParsers[*tool.Parser] {
			return Toolset{}, fmt.Errorf("toolset manifest: tools[%d] (%s) names unknown parser tool %q", i, tool.Name, *tool.Parser)
		}
	}
	if !t.Data.complete() {
		return Toolset{}, fmt.Errorf("toolset manifest: data needs nuclei_templates, semgrep_rules, trivy_db, trivy_java_db, and seclists")
	}
	for i, w := range t.Wordlists {
		if strings.TrimSpace(w.Name) == "" || !strings.HasPrefix(w.Path, "/") || len(w.SHA256) != 64 {
			return Toolset{}, fmt.Errorf("toolset manifest: wordlists[%d] is malformed", i)
		}
	}
	return t, nil
}

// EmbeddedToolset is the manifest compiled into this binary from the pinned
// image, so the toolset is known before a container exists (§9).
func EmbeddedToolset() (Toolset, error) { return ParseToolset([]byte(ToolsetManifest)) }

// Describe renders a manifest as the turn content an operator-pinned image's
// toolset arrives as (docs/sandbox-image.md §9): the same facts the pinned
// image's prompt section carries, delivered when they become knowable.
func Describe(manifest []byte) (string, error) {
	toolset, err := ParseToolset(manifest)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sandbox toolset: %s\n", toolset.ImageVersion)
	for _, tool := range toolset.Tools {
		if tool.Parser != nil {
			fmt.Fprintf(&b, "- %s %s -> %s\n", tool.Name, tool.Version, *tool.Parser)
			continue
		}
		fmt.Fprintf(&b, "- %s %s -> no parser tool; parse the output yourself\n", tool.Name, tool.Version)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// SameToolset reports whether a manifest read from the running image declares
// the same toolset as the compiled-in copy. A mismatch means the binary and the
// image were built out of step, and running it would make the prompt lie about
// what is installed (§6.3).
func SameToolset(embedded Toolset, manifest []byte) error {
	actual, err := ParseToolset(manifest)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(embedded, actual) {
		return fmt.Errorf("the image's toolset manifest (%s) does not match the one compiled into this binary (%s)", actual.ImageVersion, embedded.ImageVersion)
	}
	return nil
}

// Canonical renders the manifest as the compact, sorted JSON the pin embeds, so
// the cache's copy and the compiled-in constant cannot differ by whitespace.
func (t Toolset) Canonical() ([]byte, error) {
	return json.Marshal(t)
}
