package engagementstate

import (
	"fmt"
	"strings"
)

// Text renders a snapshot as a compact listing: one line per record, ids first
// so a follow-up call can name them, and a header with the revision and counts.
//
// Two things are deliberately never rendered. A credential's secret prints as
// `<redacted>`, because secrets never enter model context (§3.3 of the spec,
// §10.5) — the store holds them for tooling, not for the transcript. And
// evidence is summarized by count, never by its ref, so a query result cannot
// re-expose a captured excerpt (a CLI transcript or an HTTP response is quite
// capable of carrying a secret of its own).
func (s Snapshot) Text() string {
	var b strings.Builder
	header := fmt.Sprintf("state revision %d: %d entit(y/ies), %d finding(s), %d edge(s)",
		s.Revision, len(s.Entities), len(s.Findings), len(s.Edges))
	if s.Truncated {
		header += " (truncated; raise limit or narrow the query)"
	}
	b.WriteString(header)
	b.WriteByte('\n')

	for _, e := range s.Entities {
		fmt.Fprintf(&b, "%s %s %s %s\n", e.Kind, e.ID, activeWord(e.Active), describeEntity(e))
	}
	for _, f := range s.Findings {
		fmt.Fprintf(&b, "finding %s %s [%s] %s status=%s confidence=%s verification=%s affected=%s evidence=%d\n",
			f.ID, activeWord(f.Active), f.Severity, f.Title, f.Status, f.Confidence, f.Verification,
			joinOrNone(f.Affected), len(f.Evidence))
	}
	for _, edge := range s.Edges {
		fmt.Fprintf(&b, "edge %s %s -> %s confidence=%s\n", edge.Type, edge.From, edge.To, edge.Confidence)
	}
	if len(s.Entities) == 0 && len(s.Findings) == 0 {
		b.WriteString("no matching records\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// activeWord renders an envelope's active flag.
func activeWord(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

// joinOrNone renders a list, or "none" when it is empty.
func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

// describeEntity renders one entity's attributes, redacting credential
// secrets.
func describeEntity(e Entity) string {
	switch e.Kind {
	case KindHost:
		parts := []string{"addresses=" + joinOrNone(e.Addresses)}
		if e.Hostname != "" {
			parts = append(parts, "hostname="+e.Hostname)
		}
		if e.OS != "" {
			parts = append(parts, "os="+e.OS)
		}
		if len(e.Tags) > 0 {
			parts = append(parts, "tags="+strings.Join(e.Tags, ","))
		}
		return strings.Join(parts, " ")
	case KindService:
		parts := []string{
			"host=" + e.Host,
			fmt.Sprintf("port=%d/%s", e.Port, e.Proto),
			"state=" + e.State,
		}
		if e.Product != "" {
			parts = append(parts, "product="+e.Product)
		}
		if e.Version != "" {
			parts = append(parts, "version="+e.Version)
		}
		if len(e.Tags) > 0 {
			parts = append(parts, "tags="+strings.Join(e.Tags, ","))
		}
		return strings.Join(parts, " ")
	case KindCredential:
		parts := []string{"type=" + e.Type, "principal=" + e.Principal, "secret=<redacted>"}
		if len(e.Tags) > 0 {
			parts = append(parts, "tags="+strings.Join(e.Tags, ","))
		}
		return strings.Join(parts, " ")
	case KindAccess:
		parts := []string{"principal=" + e.Principal, "target=" + e.Target, "level=" + e.Level}
		if e.Via != "" {
			parts = append(parts, "via="+e.Via)
		}
		return strings.Join(parts, " ")
	case KindSegment:
		return "label=" + e.Label + " cidrs=" + joinOrNone(e.CIDRs)
	}
	return e.ID
}
