package apispec

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// serverTemplateVar matches an OpenAPI server URL variable (`{region}`).
var serverTemplateVar = regexp.MustCompile(`\{([A-Za-z0-9_.-]+)\}`)

// httpMethods is the closed set of OpenAPI path-item operation keys, in a
// stable order.
var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// extractOpenAPI reads an OpenAPI 3.0/3.1 document (§2.1, §3.1). Servers may be
// declared at root, path, and operation level; each level replaces the one
// above it, and an operation's effective server is the nearest declaration.
func extractOpenAPI(doc map[string]any, format string) (*document, error) {
	out := &document{
		format:   format,
		auth:     securityRequirements(doc),
		redacted: countLiteralCredentials(doc),
	}

	root := serverDecls(doc["servers"], nil)
	out.servers = append(out.servers, root...)
	if len(root) == 0 {
		out.noServer = "declares no server at all: an OpenAPI document with no servers entry has no base URL to authorize"
	}

	paths := getMap(doc, "paths")
	rootSecurity := strList(doc["security"])
	for _, path := range sortedKeys(paths) {
		item := getMap(paths, path)
		if item == nil {
			out.skipped = append(out.skipped, Skipped{Record: path, Reason: "path item is not a mapping"})
			continue
		}
		if !strings.HasPrefix(path, "/") {
			out.skipped = append(out.skipped, Skipped{Record: path, Reason: "path template does not start with '/'"})
			continue
		}

		inherited := root
		if raw := item["servers"]; raw != nil {
			inherited = serverDecls(raw, root)
			out.servers = append(out.servers, inherited...)
		}

		for _, method := range httpMethods {
			op := getMap(item, method)
			if op == nil {
				continue
			}
			servers := inherited
			if raw := op["servers"]; raw != nil {
				servers = serverDecls(raw, inherited)
				out.servers = append(out.servers, servers...)
			}
			auth := rootSecurity
			if declared := strList(op["security"]); len(declared) > 0 {
				auth = declared
			}
			out.operations = append(out.operations, operationDecl{
				method:      strings.ToUpper(method),
				path:        path,
				servers:     servers,
				auth:        auth,
				fingerprint: fingerprintNode([]any{op, item["parameters"]}),
			})
		}
	}
	return out, nil
}

// extractSwagger reads a Swagger 2.0 document. Its single server is `host` +
// `basePath`, once per declared scheme; a relative-only document declares no
// host and is a refusal (§7).
func extractSwagger(doc map[string]any) (*document, error) {
	out := &document{
		format:   "swagger-2.0",
		auth:     securityRequirements(doc),
		redacted: countLiteralCredentials(doc),
	}

	host := strings.TrimSpace(getString(doc, "host"))
	if host == "" {
		return &document{
			format:   out.format,
			noServer: "declares no server: swagger: 2.0 without a host is relative-only, so there is nothing to authorize",
		}, nil
	}
	basePath := strings.TrimSpace(getString(doc, "basePath"))
	schemes := strList(doc["schemes"])
	if len(schemes) == 0 {
		schemes = []string{"https"}
	}
	for _, scheme := range schemes {
		raw := scheme + "://" + host + basePath
		out.servers = append(out.servers, renderAbsolute(raw, "", nil))
	}

	paths := getMap(doc, "paths")
	rootSecurity := strList(doc["security"])
	for _, path := range sortedKeys(paths) {
		item := getMap(paths, path)
		if item == nil {
			out.skipped = append(out.skipped, Skipped{Record: path, Reason: "path item is not a mapping"})
			continue
		}
		if !strings.HasPrefix(path, "/") {
			out.skipped = append(out.skipped, Skipped{Record: path, Reason: "path template does not start with '/'"})
			continue
		}
		for _, method := range httpMethods {
			op := getMap(item, method)
			if op == nil {
				continue
			}
			auth := rootSecurity
			if declared := strList(op["security"]); len(declared) > 0 {
				auth = declared
			}
			out.operations = append(out.operations, operationDecl{
				method:      strings.ToUpper(method),
				path:        path,
				servers:     out.servers,
				auth:        auth,
				fingerprint: fingerprintNode([]any{op, item["parameters"]}),
			})
		}
	}
	return out, nil
}

// serverDecls renders one `servers` block. inherited is the enclosing level's
// declaration set: an entry's relative URL resolves against the first absolute
// URL among them, and an entry with no usable base is refused rather than
// guessed.
func serverDecls(raw any, inherited []serverDecl) []serverDecl {
	entries := asSlice(raw)
	if raw == nil {
		return nil
	}
	if entries == nil {
		return []serverDecl{{reason: "the servers entry is not a sequence"}}
	}
	base := firstAbsoluteURL(inherited)
	decls := make([]serverDecl, 0, len(entries))
	for _, entry := range entries {
		rawURL := ""
		vars := map[string]string{}
		switch e := entry.(type) {
		case string:
			rawURL = e
		default:
			m := asMap(entry)
			if m == nil {
				decls = append(decls, serverDecl{reason: "a servers entry is neither a URL nor a mapping with a url"})
				continue
			}
			rawURL = getString(m, "url")
			for name, spec := range getMap(m, "variables") {
				if def := getString(asMap(spec), "default"); def != "" {
					vars[name] = def
				}
			}
		}
		if strings.TrimSpace(rawURL) == "" {
			decls = append(decls, serverDecl{reason: "a servers entry declares no url"})
			continue
		}
		decls = append(decls, renderAbsolute(rawURL, base, vars))
	}
	return decls
}

// renderAbsolute substitutes a server URL template's variables and resolves a
// relative URL against base. An undefined variable, or a relative URL with no
// absolute base, becomes the declaration's refusal reason instead of a guess.
func renderAbsolute(raw, base string, vars map[string]string) serverDecl {
	decl := serverDecl{raw: strings.TrimSpace(raw)}
	rendered, variable := substituteServerVars(decl.raw, vars)
	if variable != "" {
		decl.variable = variable
		decl.reason = fmt.Sprintf("unresolved: {%s} — no default in the document", variable)
		return decl
	}
	parsed, err := url.Parse(rendered)
	if err == nil && parsed.Scheme != "" {
		decl.url = rendered
		return decl
	}
	if base == "" {
		decl.reason = fmt.Sprintf("%q is a relative server URL with no absolute base: the document declares no host", rendered)
		return decl
	}
	decl.url = joinURL(base, rendered)
	return decl
}

// substituteServerVars replaces every `{name}` with its default value and
// reports the first undefined name.
func substituteServerVars(raw string, vars map[string]string) (string, string) {
	undefined := ""
	out := serverTemplateVar.ReplaceAllStringFunc(raw, func(match string) string {
		name := match[1 : len(match)-1]
		value, ok := vars[name]
		if !ok || strings.TrimSpace(value) == "" {
			if undefined == "" {
				undefined = name
			}
			return match
		}
		return value
	})
	return out, undefined
}

// firstAbsoluteURL returns the first absolute URL among a declaration set.
func firstAbsoluteURL(decls []serverDecl) string {
	for _, decl := range decls {
		if decl.url != "" {
			return decl.url
		}
	}
	return ""
}

// joinURL resolves a relative server URL against an absolute base's origin and
// path.
func joinURL(base, relative string) string {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" {
		return relative
	}
	if !strings.HasPrefix(relative, "/") {
		prefix := strings.TrimSuffix(parsed.Path, "/")
		relative = prefix + "/" + relative
	}
	return parsed.Scheme + "://" + parsed.Host + relative
}

// securityRequirements reads the document's declared security schemes
// (§4.3): the scheme's name, type, and where it travels — never a value. Both
// OpenAPI 3's components.securitySchemes and Swagger 2's securityDefinitions
// use the same shape.
func securityRequirements(doc map[string]any) []AuthRequirement {
	schemes := getMap(getMap(doc, "components"), "securitySchemes")
	if schemes == nil {
		schemes = getMap(doc, "securityDefinitions")
	}
	if len(schemes) == 0 {
		return nil
	}
	out := make([]AuthRequirement, 0, len(schemes))
	for _, name := range sortedKeys(schemes) {
		scheme := getMap(schemes, name)
		if scheme == nil {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(getString(scheme, "type")))
		req := AuthRequirement{Scheme: name, Type: typ}
		switch typ {
		case "apikey":
			req.In = strings.ToLower(strings.TrimSpace(getString(scheme, "in")))
			if req.In == "" {
				req.In = "header"
			}
			req.Name = strings.TrimSpace(getString(scheme, "name"))
		case "http":
			req.In = "header"
			req.Name = "Authorization"
		case "basic":
			// Swagger 2.0's `basic` is HTTP basic auth.
			req.Type = "http"
			req.In = "header"
			req.Name = "Authorization"
		case "oauth2", "openidconnect":
			req.Type = "oauth2"
			if typ == "openidconnect" {
				req.Type = "openIdConnect"
			}
			req.In = "header"
			req.Name = "Authorization"
		default:
			req.In = "header"
			req.Name = "Authorization"
		}
		out = append(out, req)
	}
	return out
}

// secretParameterNames are the parameter names whose literal example is a
// credential worth counting (never echoing).
var secretParameterNames = map[string]bool{
	"authorization": true, "api-key": true, "apikey": true, "x-api-key": true,
	"token": true, "access-token": true, "x-auth-token": true, "cookie": true,
}

// countLiteralCredentials counts the literal credential values a document
// carries (§4.3): a security scheme's example, and a header, query, or cookie
// parameter whose name marks it and whose example is literal. The values are
// counted only — nothing here returns one.
func countLiteralCredentials(doc map[string]any) int {
	count := 0
	schemes := getMap(getMap(doc, "components"), "securitySchemes")
	if schemes == nil {
		schemes = getMap(doc, "securityDefinitions")
	}
	for _, name := range sortedKeys(schemes) {
		scheme := getMap(schemes, name)
		if literalValue(getString(scheme, "example")) {
			count++
		}
	}
	for _, path := range sortedKeys(getMap(doc, "paths")) {
		item := getMap(getMap(doc, "paths"), path)
		for _, method := range httpMethods {
			op := getMap(item, method)
			count += countLiteralParameters(asSlice(op["parameters"]))
		}
		count += countLiteralParameters(asSlice(item["parameters"]))
	}
	return count
}

// countLiteralParameters counts literal examples on credential-shaped
// parameters.
func countLiteralParameters(params []any) int {
	count := 0
	for _, param := range params {
		m := asMap(param)
		where := strings.ToLower(strings.TrimSpace(getString(m, "in")))
		if where != "header" && where != "query" && where != "cookie" {
			continue
		}
		if !secretParameterNames[strings.ToLower(strings.TrimSpace(getString(m, "name")))] {
			continue
		}
		if literalValue(getString(m, "example")) {
			count++
		}
	}
	return count
}

// literalValue reports whether a declared value is a literal (not a variable
// template) worth counting as a redacted credential.
func literalValue(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && !strings.HasPrefix(value, "{{") && !strings.HasPrefix(value, "{")
}
