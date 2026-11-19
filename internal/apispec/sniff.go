package apispec

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrNotDeclaration is the sentinel every format refusal wraps: a document
// that is unreadable, unrecognized, or in a format this tool does not load.
// Nothing is written when one is returned (§7).
var ErrNotDeclaration = errors.New("apispec: the document is not an API declaration")

// maxSampleBytes is how much of a refused document the error quotes back.
const maxSampleBytes = 240

// DocumentError is one refusal: the file it read, why it is not a declaration,
// and a sample of what it found instead (§7 requires the file, the expected
// keys, and a sample — never a loose sniff).
type DocumentError struct {
	// Artifact is the document as the caller named it.
	Artifact string
	// Detail names what was expected and what was found.
	Detail string
	// Sample is the head of the document, for a human or model to recognize.
	Sample string
}

// Error implements error.
func (e *DocumentError) Error() string {
	msg := fmt.Sprintf("%s: %s: not an API declaration (%s)", ToolName, e.Artifact, e.Detail)
	if e.Sample != "" {
		msg += "; read: " + strconv.Quote(e.Sample)
	}
	return msg + "; nothing was written"
}

// Unwrap reports the refusal's sentinel, so callers branch on the kind.
func (e *DocumentError) Unwrap() error { return ErrNotDeclaration }

// recordedKeys is the set of distinguishing keys the sniffer looked for, in the
// order the contract lists them.
const recordedKeys = `openapi 3.0/3.1, swagger 2.0, or info.schema on schema.getpostman.com`

// parseDocument decodes a document and extracts its surface. JSON and YAML go
// through the one decoder, and the format is sniffed by a distinguishing key —
// never a regex over a human-readable blob (§2.1).
func parseDocument(artifact string, data []byte) (*document, error) {
	var root any
	if err := yaml.Unmarshal(data, &root); err != nil {
		// A named unsupported format may not decode at all (GraphQL SDL and
		// WSDL rarely do); name it rather than reporting a decoder error about
		// a format the tool was never going to load.
		if named := namedUnsupported(nil, string(data)); named != "" {
			return nil, refusal(artifact, data, fmt.Sprintf("%s is not one of the formats this tool loads (looked for %s)", named, recordedKeys))
		}
		return nil, &DocumentError{
			Artifact: artifact,
			Detail:   "the bytes do not decode as JSON or YAML: " + collapse(err.Error()),
			Sample:   collapse(string(data[:min(len(data), maxSampleBytes)])),
		}
	}
	doc := asMap(root)
	if doc == nil {
		return nil, refusal(artifact, data, "the document is not a mapping at the top level")
	}

	if version := strings.TrimSpace(getString(doc, "openapi")); version != "" {
		switch {
		case strings.HasPrefix(version, "3.0"), strings.HasPrefix(version, "3.1"):
			return extractOpenAPI(doc, "openapi-"+version[:3])
		default:
			return nil, &DocumentError{
				Artifact: artifact,
				Detail:   fmt.Sprintf("openapi %s is not a supported version (this tool reads 3.0 and 3.1)", version),
				Sample:   collapse(string(data[:min(len(data), maxSampleBytes)])),
			}
		}
	}

	if version := strings.TrimSpace(getString(doc, "swagger")); version != "" {
		if version == "2.0" {
			return extractSwagger(doc)
		}
		return nil, &DocumentError{
			Artifact: artifact,
			Detail:   fmt.Sprintf("swagger %s is not a supported version (this tool reads 2.0)", version),
			Sample:   collapse(string(data[:min(len(data), maxSampleBytes)])),
		}
	}

	if info := getMap(doc, "info"); info != nil {
		if schema := strings.TrimSpace(getString(info, "schema")); strings.Contains(schema, "schema.getpostman.com") {
			if strings.Contains(schema, "v2.1") {
				return extractPostman(doc)
			}
			return nil, &DocumentError{
				Artifact: artifact,
				Detail:   fmt.Sprintf("Postman schema %s is not a supported version (this tool reads v2.1)", schema),
				Sample:   collapse(string(data[:min(len(data), maxSampleBytes)])),
			}
		}
	}

	return nil, refusal(artifact, data, unrecognizedDetail(doc, data))
}

// refusal builds the unrecognized-document error with a sample attached.
func refusal(artifact string, data []byte, detail string) error {
	return &DocumentError{
		Artifact: artifact,
		Detail:   detail,
		Sample:   collapse(string(data[:min(len(data), maxSampleBytes)])),
	}
}

// unrecognizedDetail names what the sniffer looked for, what it found instead,
// and — for a format this tool deliberately does not load — the format by name.
func unrecognizedDetail(doc map[string]any, data []byte) string {
	if named := namedUnsupported(doc, string(data)); named != "" {
		return fmt.Sprintf("%s is not one of the formats this tool loads (looked for %s); %s would be a different extraction design",
			named, recordedKeys, named)
	}
	found := sortedKeys(doc)
	if len(found) == 0 {
		return "looked for " + recordedKeys + "; found a document with no top-level keys"
	}
	if len(found) > 8 {
		found = found[:8]
	}
	return fmt.Sprintf("looked for %s; found top-level keys: %s", recordedKeys, strings.Join(found, ", "))
}

// namedUnsupported names the formats the contract refuses by name rather than
// sniffing loosely: Swagger 1.x, RAML, API Blueprint, WSDL, GraphQL SDL, and
// Protocol Buffers. It only runs once the accepted keys are absent, so a
// description that mentions "type Query" cannot mislabel a real OpenAPI file.
func namedUnsupported(doc map[string]any, text string) string {
	if _, ok := doc["swaggerVersion"]; ok {
		return "Swagger 1.x"
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "#%raml"):
		return "RAML"
	case strings.Contains(lower, "format: 1a"), strings.Contains(lower, "format: 1b"):
		return "API Blueprint"
	case strings.Contains(lower, "<definitions"), strings.Contains(lower, "wsdl:"):
		return "WSDL"
	case strings.Contains(lower, `syntax = "proto`), strings.Contains(lower, `syntax="proto`):
		return "Protocol Buffers"
	case strings.Contains(lower, "type query"), strings.Contains(lower, "type mutation"), strings.HasPrefix(strings.TrimSpace(lower), "schema {"):
		return "GraphQL SDL"
	}
	return ""
}

// readDocument reads a document under the size ceiling (§7), so an oversized
// file is a clear error instead of an OOM.
func readDocument(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not an API document", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > MaxDocumentBytes {
		return nil, fmt.Errorf("%s is %d bytes; api_spec_load reads at most %d bytes", path, info.Size(), MaxDocumentBytes)
	}
	//nolint:gosec // the path was confined to the session workspace by the tool.
	return os.ReadFile(path)
}
