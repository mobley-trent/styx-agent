// Package findingsexport renders a run's reportable findings into the three
// artifacts decided in docs/findings-export.md: vulnerabilities.json,
// vulnerabilities.csv, and findings.sarif.
//
// Boundary rule: this package is a pure projection of engagement state. It
// does no I/O, reads no clock, and touches no store, so identical state renders
// byte-identical artifacts (ADR-0008). It adds no fact of its own: no severity,
// no score, no remediation, and never a verdict.
package findingsexport

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// SchemaVersion is the export format's own version, independent of the
// engagement store's (§3.1). A change to the shape is a decided v2, never
// inferred by a reader.
const SchemaVersion = 1

// The three artifact names (§5).
const (
	// JSONName is the primary machine record.
	JSONName = "vulnerabilities.json"
	// CSVName is the DefectDojo-shaped row set.
	CSVName = "vulnerabilities.csv"
	// SARIFName is the SARIF 2.1.0 projection.
	SARIFName = "findings.sarif"
)

// Files is one rendering of a snapshot: the three artifacts, ready to write.
type Files struct {
	// JSON, CSV, and SARIF are the complete file contents, newline-terminated.
	JSON  []byte
	CSV   []byte
	SARIF []byte
}

// Counts reports how many findings a snapshot exports and how many it omits
// (§2). It is what the stderr line names, and it agrees with Render because
// both read the same predicate.
func Counts(snap engagementstate.Snapshot) (reported, omitted int) {
	for _, f := range snap.Findings {
		if Reportable(f) {
			reported++
			continue
		}
		omitted++
	}
	return reported, omitted
}

// Reportable is §2's one predicate: the definition of "a finding this export
// carries". The severity gate reads it minus Gated's exclusion, so the artifact
// and the gate cannot disagree about which findings exist.
func Reportable(f engagementstate.Finding) bool {
	if !f.Active || f.Verification == engagementstate.VerificationRefuted {
		return false
	}
	switch f.Status {
	case engagementstate.StatusDetected, engagementstate.StatusConfirmed, engagementstate.StatusRiskAccepted:
		return true
	}
	return false
}

// Gated reports whether a finding may fail a severity gate: reportable but not
// risk_accepted (§2, docs/headless-ci.md §8.2). Risk someone consciously took
// is exported and never gated.
func Gated(f engagementstate.Finding) bool {
	return Reportable(f) && f.Status != engagementstate.StatusRiskAccepted
}

// Threshold resolves a --fail-on value to a store severity: the five lowercase
// severities and nothing else (docs/headless-ci.md §8.4).
func Threshold(value string) (engagementstate.Severity, bool) {
	switch s := engagementstate.Severity(value); s {
	case engagementstate.SeverityCritical, engagementstate.SeverityHigh,
		engagementstate.SeverityMedium, engagementstate.SeverityLow, engagementstate.SeverityInfo:
		return s, true
	}
	return "", false
}

// GatedFindings counts what the severity gate must say about a snapshot
// (docs/headless-ci.md §8.2): how many gated findings are at or above the
// threshold, and how many of those are unverified (§8.7's disclosure). It
// counts and adds nothing; the verdict — an exit code — belongs to the run
// (ADR-0009).
func GatedFindings(snap engagementstate.Snapshot, threshold engagementstate.Severity) (failing, unverified int) {
	at := severityRank(threshold)
	for _, f := range snap.Findings {
		if !Gated(f) || severityRank(f.Severity) < at {
			continue
		}
		failing++
		if f.Verification == engagementstate.VerificationUnverified {
			unverified++
		}
	}
	return failing, unverified
}

// Render projects a snapshot into the three artifacts. engagement is the
// engagement's name, empty for a safe-mode run, which renders a valid empty
// export (§5); version is the build's version, carried as SARIF's
// semanticVersion (§7.1).
func Render(snap engagementstate.Snapshot, engagement, version string) (Files, error) {
	rows := make([]rendered, 0, len(snap.Findings))
	omitted := 0
	for _, f := range snap.Findings {
		if !Reportable(f) {
			omitted++
			continue
		}
		rows = append(rows, resolve(snap, f))
	}
	sortRows(rows)
	rules := rulesFor(rows)

	var files Files
	var err error
	if files.JSON, err = renderJSON(engagement, rows, omitted); err != nil {
		return Files{}, err
	}
	if files.CSV, err = renderCSV(rows); err != nil {
		return Files{}, err
	}
	if files.SARIF, err = renderSARIF(version, rows, rules); err != nil {
		return Files{}, err
	}
	return files, nil
}

// rendered is one reportable finding with everything the three renderings need
// resolved once: its endpoints, its ordering key, its rule slug, and its
// fingerprint.
type rendered struct {
	finding     engagementstate.Finding
	endpoints   []endpoint
	orderKey    string
	title       string
	fingerprint string
}

// endpoint is one resolved affected endpoint (§3.2). A ref that does not
// resolve becomes kind "unknown" with the raw ref, never a dropped endpoint.
type endpoint struct {
	Kind     string `json:"kind"`
	Host     string `json:"host,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Ref      string `json:"ref,omitempty"`
}

// resolve builds the rendered finding: endpoints resolved from the snapshot
// and the ordering key that makes the sort total (§4).
func resolve(snap engagementstate.Snapshot, f engagementstate.Finding) rendered {
	endpoints := make([]endpoint, 0, len(f.Affected))
	keys := make([]string, 0, len(f.Affected))
	for _, ref := range f.Affected {
		ep := resolveRef(snap, ref)
		endpoints = append(endpoints, ep)
		keys = append(keys, ep.key())
	}
	return rendered{
		finding:     f,
		endpoints:   endpoints,
		orderKey:    strings.Join(keys, ","),
		title:       f.Title,
		fingerprint: fingerprint(f.Title, f.Affected),
	}
}

// resolveRef resolves one affected ref: a host ref becomes its primary address
// and hostname, a service ref becomes its host's coordinates plus its own
// port, proto, product, and version. A deactivated or missing endpoint is
// carried as unknown rather than dropped (§3.2).
func resolveRef(snap engagementstate.Snapshot, ref string) endpoint {
	e, ok := snap.Entity(ref)
	if !ok || !e.Active {
		return endpoint{Kind: "unknown", Ref: ref}
	}
	switch e.Kind {
	case engagementstate.KindHost:
		return hostEndpoint(e)
	case engagementstate.KindService:
		host, ok := snap.Entity(e.Host)
		if !ok || !host.Active || host.Kind != engagementstate.KindHost {
			return endpoint{Kind: "unknown", Ref: ref}
		}
		ep := hostEndpoint(host)
		ep.Kind = string(engagementstate.KindService)
		ep.Port = e.Port
		ep.Proto = e.Proto
		ep.Product = e.Product
		ep.Version = e.Version
		return ep
	}
	return endpoint{Kind: "unknown", Ref: ref}
}

// hostEndpoint is a host's coordinates: its primary address and hostname.
func hostEndpoint(e engagementstate.Entity) endpoint {
	ep := endpoint{Kind: string(engagementstate.KindHost), Hostname: e.Hostname}
	if len(e.Addresses) > 0 {
		ep.Host = e.Addresses[0]
	}
	return ep
}

// address is the endpoint's address, falling back to its hostname when the
// address is unknown (§7.3).
func (e endpoint) address() string {
	if e.Host != "" {
		return e.Host
	}
	return e.Hostname
}

// key renders the endpoint for the total order (§4). It is a projection of the
// resolved record, so two runs over the same state join the same string.
func (e endpoint) key() string {
	if e.Kind == "unknown" {
		return "unknown|" + e.Ref
	}
	return strings.Join([]string{
		e.Kind, e.Host, e.Hostname, strconv.Itoa(e.Port), e.Proto, e.Product, e.Version,
	}, "|")
}

// url is the CSV `Url` cell: address:port/proto for a service, the address for
// a host, the raw ref when it did not resolve (§6).
func (e endpoint) url() string {
	switch e.Kind {
	case string(engagementstate.KindHost):
		return e.address()
	case string(engagementstate.KindService):
		return e.address() + ":" + strconv.Itoa(e.Port) + "/" + e.Proto
	default:
		return e.Ref
	}
}

// uri is the SARIF location URI: a scheme-less, relative-shaped path, because
// a host finding is not a source file (§7.3). Empty means no location.
func (e endpoint) uri() string {
	switch e.Kind {
	case string(engagementstate.KindHost):
		return "host/" + e.address()
	case string(engagementstate.KindService):
		return "service/" + e.url()
	}
	return ""
}

// SortRows orders findings by severity (critical → info), then title, then the
// joined affected endpoints, then id — a total order with nothing iterating a
// map (§4).
func sortRows(rows []rendered) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ra, rb := severityRank(a.finding.Severity), severityRank(b.finding.Severity); ra != rb {
			return ra > rb
		}
		if a.title != b.title {
			return a.title < b.title
		}
		if a.orderKey != b.orderKey {
			return a.orderKey < b.orderKey
		}
		return a.finding.ID < b.finding.ID
	})
}

// severityRank orders severities critical → info for the export's sort.
func severityRank(s engagementstate.Severity) int {
	switch s {
	case engagementstate.SeverityCritical:
		return 5
	case engagementstate.SeverityHigh:
		return 4
	case engagementstate.SeverityMedium:
		return 3
	case engagementstate.SeverityLow:
		return 2
	case engagementstate.SeverityInfo:
		return 1
	}
	return 0
}

// fingerprint is the 16-hex-character digest of the store's own natural key —
// the title and the sorted affected refs, joined by U+001F (§7.5).
func fingerprint(title string, refs []string) string {
	sorted := append([]string(nil), refs...)
	sort.Strings(sorted)
	material := strings.Join(append([]string{title}, sorted...), "\x1f")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:8])
}

// rule is one SARIF rule: a slug of a title, plus the title it stands for.
type rule struct {
	id    string
	title string
}

// rulesFor assigns one rule per distinct title in the export. Slugs are
// assigned in sorted-title order, so a collision takes -2, -3 deterministically
// (§7.1).
func rulesFor(rows []rendered) []rule {
	seen := make(map[string]bool, len(rows))
	titles := make([]string, 0, len(rows))
	for _, r := range rows {
		if seen[r.title] {
			continue
		}
		seen[r.title] = true
		titles = append(titles, r.title)
	}
	sort.Strings(titles)

	used := make(map[string]bool, len(titles))
	rules := make([]rule, 0, len(titles))
	for _, title := range titles {
		base := slug(title)
		id := base
		for n := 2; used[id]; n++ {
			id = base + "-" + strconv.Itoa(n)
		}
		used[id] = true
		rules = append(rules, rule{id: id, title: title})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].id < rules[j].id })
	return rules
}

// slug folds a title into a lowercase ASCII rule id: runs of non-alphanumerics
// become "-", and the ends are trimmed (§7.1). A title with no alphanumerics
// falls back to "finding", which the collision pass then disambiguates.
func slug(title string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(title) {
		alnum := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if !alnum {
			pendingDash = true
			continue
		}
		if pendingDash && b.Len() > 0 {
			b.WriteByte('-')
		}
		pendingDash = false
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "finding"
	}
	return b.String()
}

// The JSON document (§3).

type document struct {
	SchemaVersion int       `json:"schema_version"`
	Engagement    *string   `json:"engagement"`
	Findings      []finding `json:"findings"`
	Counts        counts    `json:"counts"`
}

type counts struct {
	Reported int `json:"reported"`
	Omitted  int `json:"omitted"`
}

type finding struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Severity     string     `json:"severity"`
	CVSSVector   string     `json:"cvss_vector,omitempty"`
	Status       string     `json:"status"`
	Confidence   string     `json:"confidence"`
	Verification string     `json:"verification"`
	Affected     []endpoint `json:"affected"`
	Evidence     evidence   `json:"evidence"`
	FirstSeen    string     `json:"first_seen"`
	LastSeen     string     `json:"last_seen"`
}

type evidence struct {
	Count int            `json:"count"`
	Items []evidenceItem `json:"items"`
}

type evidenceItem struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// renderJSON writes the primary machine record: two-space indented JSON with a
// trailing newline, keys in the declared struct order (§4).
func renderJSON(engagement string, rows []rendered, omitted int) ([]byte, error) {
	doc := document{
		SchemaVersion: SchemaVersion,
		Findings:      make([]finding, 0, len(rows)),
		Counts:        counts{Reported: len(rows), Omitted: omitted},
	}
	if engagement != "" {
		name := engagement
		doc.Engagement = &name
	}
	for _, r := range rows {
		f := r.finding
		items := make([]evidenceItem, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			items = append(items, evidenceItem{Kind: string(e.Kind), Ref: e.Ref})
		}
		doc.Findings = append(doc.Findings, finding{
			ID:           f.ID,
			Title:        f.Title,
			Severity:     string(f.Severity),
			CVSSVector:   f.CVSSVector,
			Status:       string(f.Status),
			Confidence:   string(f.Confidence),
			Verification: string(f.Verification),
			Affected:     r.endpoints,
			Evidence:     evidence{Count: len(f.Evidence), Items: items},
			FirstSeen:    timestamp(f.FirstSeen),
			LastSeen:     timestamp(f.LastSeen),
		})
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// timestamp renders a record timestamp as RFC 3339 UTC. It comes from the
// store, so it is deterministic (§4).
func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// csvHeader is DefectDojo's generic findings CSV column names, where they apply
// (§6).
var csvHeader = []string{
	"Date", "Title", "Severity", "Url", "Id", "Status", "Confidence", "Verification", "EvidenceCount",
}

// renderCSV writes one row per finding × affected endpoint — or one row with
// an empty Url when nothing resolved — with RFC 4180 quoting and LF
// terminators (§6).
func renderCSV(rows []rendered) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(csvHeader); err != nil {
		return nil, err
	}
	for _, r := range rows {
		f := r.finding
		base := []string{
			timestamp(f.LastSeen),
			f.Title,
			severityLabel(f.Severity),
			"",
			f.ID,
			string(f.Status),
			string(f.Confidence),
			string(f.Verification),
			strconv.Itoa(len(f.Evidence)),
		}
		if len(r.endpoints) == 0 {
			if err := w.Write(base); err != nil {
				return nil, err
			}
			continue
		}
		for _, ep := range r.endpoints {
			row := append([]string(nil), base...)
			row[3] = ep.url()
			if err := w.Write(row); err != nil {
				return nil, err
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// severityLabel spells a severity the way DefectDojo's importer does (§6).
func severityLabel(s engagementstate.Severity) string {
	switch s {
	case engagementstate.SeverityCritical:
		return "Critical"
	case engagementstate.SeverityHigh:
		return "High"
	case engagementstate.SeverityMedium:
		return "Medium"
	case engagementstate.SeverityLow:
		return "Low"
	case engagementstate.SeverityInfo:
		return "Info"
	}
	return string(s)
}

// The SARIF 2.1.0 projection (§7).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string           `json:"ruleId"`
	Level               string           `json:"level"`
	Message             sarifText        `json:"message"`
	Locations           []sarifLocation  `json:"locations,omitempty"`
	Properties          resultProperties `json:"properties"`
	Fingerprints        styxFingerprint  `json:"fingerprints"`
	PartialFingerprints styxFingerprint  `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical      `json:"physicalLocation"`
	Properties       locationProperties `json:"properties"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// locationProperties carries an endpoint's real structure: a scanner-specific
// bag is exactly what SARIF's properties is for (§7.3).
type locationProperties struct {
	Host     string `json:"host,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Port     int    `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type resultProperties struct {
	FindingID     string `json:"findingId"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	Confidence    string `json:"confidence"`
	Verification  string `json:"verification"`
	EvidenceCount int    `json:"evidenceCount"`
}

// styxFingerprint is the one fingerprint key both properties carry (§7.5).
type styxFingerprint struct {
	StyxFindingV1 string `json:"styxFindingV1"`
}

// renderSARIF projects the export as SARIF 2.1.0: one run, one rule per
// distinct title, one result per finding carrying all its resolvable
// endpoints. No security-severity, no invocations, no fabricated line hash
// (§7.6).
func renderSARIF(version string, rows []rendered, rules []rule) ([]byte, error) {
	ids := make(map[string]string, len(rules))
	sarifRules := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ids[r.title] = r.id
		sarifRules = append(sarifRules, sarifRule{
			ID:               r.id,
			Name:             r.title,
			ShortDescription: sarifText{Text: r.title},
		})
	}

	results := make([]sarifResult, 0, len(rows))
	for _, r := range rows {
		f := r.finding
		locations := make([]sarifLocation, 0, len(r.endpoints))
		for _, ep := range r.endpoints {
			uri := ep.uri()
			if uri == "" {
				continue
			}
			locations = append(locations, sarifLocation{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}},
				Properties: locationProperties{
					Host:     ep.Host,
					Hostname: ep.Hostname,
					Port:     ep.Port,
					Proto:    ep.Proto,
					Product:  ep.Product,
					Version:  ep.Version,
				},
			})
		}
		results = append(results, sarifResult{
			RuleID:    ids[f.Title],
			Level:     level(f.Severity),
			Message:   sarifText{Text: f.Title},
			Locations: locations,
			Properties: resultProperties{
				FindingID:     f.ID,
				Severity:      string(f.Severity),
				Status:        string(f.Status),
				Confidence:    string(f.Confidence),
				Verification:  string(f.Verification),
				EvidenceCount: len(f.Evidence),
			},
			Fingerprints:        styxFingerprint{StyxFindingV1: r.fingerprint},
			PartialFingerprints: styxFingerprint{StyxFindingV1: r.fingerprint},
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            "styx",
				SemanticVersion: version,
				InformationURI:  "https://github.com/mobley-trent/styx-agent",
				Rules:           sarifRules,
			}},
			Results: results,
		}},
	}
	encoded, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// level maps severity to SARIF's alert level (§7.4). Verification and
// confidence never move it: re-ranking a finding would be the silent downgrade
// the safety model refuses.
func level(s engagementstate.Severity) string {
	switch s {
	case engagementstate.SeverityCritical, engagementstate.SeverityHigh:
		return "error"
	case engagementstate.SeverityMedium:
		return "warning"
	case engagementstate.SeverityLow, engagementstate.SeverityInfo:
		return "note"
	}
	return "note"
}

// String names the export for a diagnostic.
func (f Files) String() string {
	return fmt.Sprintf("%s, %s, %s", JSONName, CSVName, SARIFName)
}
