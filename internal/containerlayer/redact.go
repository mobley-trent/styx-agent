package containerlayer

import (
	"net/url"
	"strings"
)

// Redacted replaces a credential in the model-facing views of a capture
// (§4.5). It is applied where the capture becomes model context, never at
// write time: the bytes on disk stay real, which is what keeps
// replay-as-captured authenticating.
const Redacted = "[redacted]"

// fixedCredentials are the header names §4.5 names outright. They are not
// split into tokens: "Authorization" carries no token from the vocabulary
// below, and neither does "Cookie".
var fixedCredentials = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"proxy-authorization": true,
}

// credentialTokens are the name tokens that make any header or query key a
// credential: X-Api-Key, access_token, client_secret, X-Session-Id.
var credentialTokens = map[string]bool{
	"token":    true,
	"key":      true,
	"secret":   true,
	"password": true,
	"session":  true,
}

// RedactExchange returns the model-facing projection of an exchange: every
// credential-bearing header and query value becomes Redacted, and the rest is
// what was captured.
func RedactExchange(ex Exchange) Exchange {
	out := cloneExchange(ex)
	out.URL = RedactURL(ex.URL)
	out.RequestHeaders = RedactHeaders(ex.RequestHeaders)
	out.ResponseHeaders = RedactHeaders(ex.ResponseHeaders)
	return out
}

// RedactHeaders copies headers with every credential value replaced.
func RedactHeaders(in []Header) []Header {
	if in == nil {
		return nil
	}
	out := make([]Header, len(in))
	for i, field := range in {
		out[i] = field
		if CredentialName(field.Name) {
			out[i].Value = Redacted
		}
	}
	return out
}

// RedactURL replaces the value of every credential-bearing query key.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return raw
	}
	changed := false
	for key := range values {
		if CredentialName(key) {
			values.Set(key, Redacted)
			changed = true
		}
	}
	if !changed {
		return raw
	}
	u.RawQuery = values.Encode()
	return u.String()
}

// CredentialName reports whether a header or query name carries a credential
// the model must never see (§4.5): one of the four named headers, or any name
// with token, key, secret, password, or session as one of its tokens.
func CredentialName(name string) bool {
	if fixedCredentials[strings.ToLower(strings.TrimSpace(name))] {
		return true
	}
	for _, token := range nameTokens(name) {
		if credentialTokens[token] {
			return true
		}
	}
	return false
}

// nameTokens splits a header or query name into lowercase tokens. A token
// boundary is a non-alphanumeric rune or a camel-case hump, so X-Api-Key and
// accessToken both expose "key" and "token".
func nameTokens(name string) []string {
	var tokens []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			tokens = append(tokens, strings.ToLower(b.String()))
			b.Reset()
		}
	}
	prevLower := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if r >= 'A' && r <= 'Z' && prevLower {
				flush()
			}
			b.WriteRune(r)
			prevLower = r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		default:
			flush()
			prevLower = false
		}
	}
	flush()
	return tokens
}
