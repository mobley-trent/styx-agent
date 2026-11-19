package apispec

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// postmanVarPattern matches a Postman variable reference (`{{baseUrl}}`).
var postmanVarPattern = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

// postmanSecretKeys are the auth-entry keys whose literal value is a credential
// worth counting (never echoing).
var postmanSecretKeys = map[string]bool{
	"value": true, "token": true, "password": true, "secret": true,
	"accesstoken": true, "clientsecret": true, "authtoken": true,
}

// extractPostman reads a Postman v2.1 collection (§3.4). A request's base URL
// comes from the document itself — the collection's variable block, shadowed by
// a folder's — and a `{{var}}` the document does not define is refused with the
// variable named. There is no environment-file search.
func extractPostman(doc map[string]any) (*document, error) {
	out := &document{format: "postman-2.1"}
	authByScheme := map[string]AuthRequirement{}
	recordAuth := func(auth any) bool {
		req, redacted, ok := postmanAuth(auth)
		if !ok {
			return false
		}
		out.redacted += redacted
		if _, seen := authByScheme[req.Scheme]; !seen {
			authByScheme[req.Scheme] = req
			out.auth = append(out.auth, req)
		}
		return true
	}
	recordAuth(doc["auth"])

	collectionVars := postmanVariables(getSlice(doc, "variable"))
	var walk func(items []any, vars map[string]string, inherited any)
	walk = func(items []any, vars map[string]string, inherited any) {
		for _, entry := range items {
			item := asMap(entry)
			if item == nil {
				out.skipped = append(out.skipped, Skipped{Record: "collection item", Reason: "item is not a mapping"})
				continue
			}
			if children := getSlice(item, "item"); children != nil {
				folderVars := mergeVars(vars, postmanVariables(getSlice(item, "variable")))
				auth := inherited
				if declared := item["auth"]; declared != nil {
					auth = declared
					recordAuth(auth)
				}
				walk(children, folderVars, auth)
				continue
			}
			request := getMap(item, "request")
			if request == nil {
				out.skipped = append(out.skipped, Skipped{Record: strings.TrimSpace(getString(item, "name")), Reason: "collection item is neither a folder nor a request"})
				continue
			}
			auth := inherited
			if declared := request["auth"]; declared != nil {
				auth = declared
				recordAuth(auth)
			}
			out.operations = append(out.operations, postmanOperation(request, vars, auth))
		}
	}
	walk(getSlice(doc, "item"), collectionVars, doc["auth"])

	// A request the extractor understood enough to reject is a skipped row, never
	// a silent drop (§7).
	kept := out.operations[:0]
	for _, op := range out.operations {
		if op.skipped != "" {
			out.skipped = append(out.skipped, Skipped{Record: op.method + " " + op.path, Reason: op.skipped})
			continue
		}
		kept = append(kept, op)
	}
	out.operations = kept

	// Every request's server is a declaration; collect them in operation order.
	for _, op := range out.operations {
		out.servers = append(out.servers, op.servers...)
	}
	if len(out.servers) == 0 {
		out.noServer = "declares no server: no request carries an absolute base URL"
	}
	sort.SliceStable(out.operations, func(i, j int) bool {
		if out.operations[i].path != out.operations[j].path {
			return out.operations[i].path < out.operations[j].path
		}
		return out.operations[i].method < out.operations[j].method
	})
	return out, nil
}

// postmanOperation renders one request as an operation: its method, its path
// with the query dropped (a query is not echoed — it can carry a key), and the
// single server its base URL names.
func postmanOperation(request map[string]any, vars map[string]string, auth any) operationDecl {
	method := strings.ToUpper(strings.TrimSpace(getString(request, "method")))
	rawURL := postmanURL(request["url"])

	op := operationDecl{method: method, fingerprint: fingerprintNode(request)}
	if req, _, ok := postmanAuth(auth); ok {
		op.auth = []string{req.Scheme}
	}
	if method == "" {
		return operationDecl{method: method, skipped: "request declares no method"}
	}
	if strings.TrimSpace(rawURL) == "" {
		return operationDecl{method: method, skipped: "request declares no url"}
	}

	expanded, variable := expandPostmanVars(rawURL, vars)
	if variable != "" {
		op.servers = []serverDecl{{
			raw:      rawURL,
			variable: variable,
			reason:   fmt.Sprintf("unresolved: {{%s}} — no value in the collection", variable),
		}}
		op.path = rawURL
		return op
	}

	parsed, err := url.Parse(expanded)
	if err != nil || parsed.Hostname() == "" {
		op.servers = []serverDecl{{raw: rawURL, reason: fmt.Sprintf("%q is not an absolute URL with a host", rawURL)}}
		op.path = rawURL
		return op
	}
	server := parsed.Scheme + "://" + parsed.Host
	op.path = parsed.EscapedPath()
	if op.path == "" {
		op.path = "/"
	}
	op.servers = []serverDecl{{raw: server, url: server}}
	return op
}

// postmanURL renders a request's url, which is a string in a minimal export and
// an object in a full one.
func postmanURL(raw any) string {
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		m := asMap(raw)
		if m == nil {
			return ""
		}
		if s := strings.TrimSpace(getString(m, "raw")); s != "" {
			return s
		}
		host := postmanJoin(m["host"], ".")
		if host == "" {
			return ""
		}
		protocol := strings.TrimSpace(getString(m, "protocol"))
		if protocol == "" {
			protocol = "https"
		}
		out := protocol + "://" + host
		if port := postmanScalar(m["port"]); port != "" {
			out += ":" + port
		}
		return out + postmanPath(m["path"])
	}
}

// postmanJoin renders a host or path part declared as a string or a list.
func postmanJoin(raw any, separator string) string {
	if s := strings.TrimSpace(asString(raw)); s != "" {
		return s
	}
	var parts []string
	for _, part := range asSlice(raw) {
		if s := postmanScalar(part); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, separator)
}

// postmanPath renders a url object's path list with a leading slash.
func postmanPath(raw any) string {
	path := postmanJoin(raw, "/")
	if path == "" {
		return ""
	}
	return "/" + strings.TrimPrefix(path, "/")
}

// postmanScalar renders a scalar declared in a url object.
func postmanScalar(raw any) string {
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

// postmanVariables reads a `variable` block into a name-to-value table. Values
// never leave this map: they are substituted into a base URL and nothing else.
func postmanVariables(raw []any) map[string]string {
	out := map[string]string{}
	for _, entry := range raw {
		m := asMap(entry)
		if m == nil || asBool(m["disabled"]) {
			continue
		}
		name := strings.TrimSpace(getString(m, "key"))
		if name == "" {
			continue
		}
		value := postmanScalar(m["value"])
		if value == "" {
			continue
		}
		out[name] = value
	}
	return out
}

// mergeVars overlays a folder's variables over the collection's, which is the
// shadowing Postman applies.
func mergeVars(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

// expandPostmanVars substitutes `{{name}}` references, reporting the first name
// the document does not define.
func expandPostmanVars(raw string, vars map[string]string) (string, string) {
	expanded := raw
	undefined := ""
	for pass := 0; pass < 5; pass++ {
		changed := false
		undefined = ""
		expanded = postmanVarPattern.ReplaceAllStringFunc(expanded, func(match string) string {
			name := match[2 : len(match)-2]
			name = strings.TrimSpace(name)
			value, ok := vars[name]
			if !ok {
				if undefined == "" {
					undefined = name
				}
				return match
			}
			changed = true
			return value
		})
		if undefined != "" || !changed {
			break
		}
	}
	return expanded, undefined
}

// postmanAuth maps one auth block onto a requirement and counts its literal
// credential values. The requirement carries the scheme's name, type, and
// location — never the value.
func postmanAuth(raw any) (AuthRequirement, int, bool) {
	block := asMap(raw)
	if block == nil {
		return AuthRequirement{}, 0, false
	}
	typ := strings.ToLower(strings.TrimSpace(getString(block, "type")))
	if typ == "" || typ == "noauth" {
		return AuthRequirement{}, 0, false
	}

	fields := map[string]string{}
	redacted := 0
	for _, entry := range getSlice(block, typ) {
		m := asMap(entry)
		if m == nil {
			continue
		}
		key := strings.TrimSpace(getString(m, "key"))
		value := strings.TrimSpace(asString(m["value"]))
		if key != "" {
			fields[key] = value
		}
		if postmanSecretKeys[strings.ToLower(key)] && literalValue(value) {
			redacted++
		}
	}

	switch typ {
	case "apikey":
		req := AuthRequirement{Scheme: "apikey", Type: "apiKey", In: "header", Name: "X-API-Key"}
		if in := strings.ToLower(strings.TrimSpace(fields["in"])); in != "" {
			req.In = in
		}
		if name := strings.TrimSpace(fields["key"]); name != "" {
			req.Name = name
		}
		return req, redacted, true
	case "bearer", "basic", "digest", "ntlm", "hawk", "awsv4", "oauth1", "oauth2", "jwt":
		return AuthRequirement{Scheme: typ, Type: "http", In: "header", Name: "Authorization"}, redacted, true
	}
	return AuthRequirement{Scheme: typ, Type: typ, In: "header", Name: "Authorization"}, redacted, true
}
