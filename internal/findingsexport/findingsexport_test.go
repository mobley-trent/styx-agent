package findingsexport_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/findingsexport"
)

// update rewrites the golden files: `go test ./internal/findingsexport -update`.
var update = flag.Bool("update", false, "rewrite the golden export files")

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

// fixtureSnapshot is a small engagement with every shape the export decides:
// a service endpoint, a host endpoint, a finding omitted by status, one omitted
// by verification, a risk_accepted finding, a title-slug collision, and a ref
// that does not resolve.
func fixtureSnapshot(t *testing.T) engagementstate.Snapshot {
	t.Helper()
	first := at(t, "2026-10-30T10:12:04Z")
	last := at(t, "2026-10-30T11:40:51Z")
	return engagementstate.Snapshot{
		SchemaVersion: 1,
		Revision:      7,
		Entities: []engagementstate.Entity{
			{
				ID: "host-1a2b", Kind: engagementstate.KindHost, Active: true,
				Addresses: []string{"10.0.0.33"}, Hostname: "web02",
			},
			{
				ID: "service-3c4d", Kind: engagementstate.KindService, Active: true,
				Host: "host-1a2b", Port: 445, Proto: engagementstate.ProtoTCP,
				Product: "microsoft-ds", Version: "10.0", State: engagementstate.StateOpen,
			},
			{
				ID: "host-2b3c", Kind: engagementstate.KindHost, Active: true,
				Addresses: []string{"10.0.0.50"}, Hostname: "ftp01",
			},
		},
		Findings: []engagementstate.Finding{
			{
				ID: "finding-eeee", Active: true, Title: "Stale TLS certificate",
				Severity: engagementstate.SeverityLow, Status: engagementstate.StatusFixed,
				Confidence: engagementstate.ConfidenceMedium, Verification: engagementstate.VerificationVerified,
				Affected: []string{"host-1a2b"}, FirstSeen: first, LastSeen: last,
			},
			{
				ID: "finding-cccc", Active: true, Title: "SMB signing disabled",
				Severity: engagementstate.SeverityHigh, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Status: engagementstate.StatusConfirmed, Confidence: engagementstate.ConfidenceHigh,
				Verification: engagementstate.VerificationUnverified,
				Affected:     []string{"service-3c4d"},
				Evidence: []engagementstate.Evidence{
					{Kind: engagementstate.EvidenceArtifact, Ref: ".styx/out/nmap-20261030T1012.xml"},
					{Kind: engagementstate.EvidenceNote, Ref: "signing required = false on 445/tcp"},
				},
				FirstSeen: first, LastSeen: last,
			},
			{
				ID: "finding-ffff", Active: true, Title: "SMB signing: disabled",
				Severity: engagementstate.SeverityMedium, Status: engagementstate.StatusDetected,
				Confidence: engagementstate.ConfidenceMedium, Verification: engagementstate.VerificationUnverified,
				Affected: []string{"host-9999"}, FirstSeen: first, LastSeen: last,
			},
			{
				ID: "finding-dddd", Active: true, Title: "Anonymous FTP read access",
				Severity: engagementstate.SeverityMedium, Status: engagementstate.StatusRiskAccepted,
				Confidence: engagementstate.ConfidenceHigh, Verification: engagementstate.VerificationVerified,
				Affected: []string{"host-2b3c"},
				Evidence: []engagementstate.Evidence{
					{Kind: engagementstate.EvidenceCLIOutput, Ref: "ftp> ls"},
				},
				FirstSeen: first, LastSeen: last,
			},
			{
				ID: "finding-aaaa", Active: true, Title: "Refuted banner",
				Severity: engagementstate.SeverityHigh, Status: engagementstate.StatusConfirmed,
				Confidence: engagementstate.ConfidenceLow, Verification: engagementstate.VerificationRefuted,
				Affected: []string{"host-2b3c"}, FirstSeen: first, LastSeen: last,
			},
		},
	}
}

// TestRenderGolden pins the three artifacts byte for byte.
func TestRenderGolden(t *testing.T) {
	files, err := findingsexport.Render(fixtureSnapshot(t), "acme-q4", "v0.4.0")
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}

	for _, c := range []struct {
		name string
		got  []byte
	}{
		{findingsexport.JSONName, files.JSON},
		{findingsexport.CSVName, files.CSV},
		{findingsexport.SARIFName, files.SARIF},
	} {
		path := filepath.Join("testdata", c.name)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(path, c.got, 0o600); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			continue
		}
		//nolint:gosec // the golden path is the one this test built from its own fixture directory.
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden %s: %v", path, err)
		}
		if !bytes.Equal(c.got, want) {
			t.Errorf("%s does not match its golden file:\n--- got ---\n%s", c.name, c.got)
		}
	}
}

// TestRenderIsDeterministic covers §4: identical state produces byte-identical
// artifacts, whatever order the store happens to hold the records in.
func TestRenderIsDeterministic(t *testing.T) {
	snap := fixtureSnapshot(t)
	first, err := findingsexport.Render(snap, "acme-q4", "v0.4.0")
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	second, err := findingsexport.Render(snap, "acme-q4", "v0.4.0")
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	assertSameFiles(t, first, second)

	reversed := snap
	reversed.Findings = make([]engagementstate.Finding, 0, len(snap.Findings))
	for i := len(snap.Findings) - 1; i >= 0; i-- {
		reversed.Findings = append(reversed.Findings, snap.Findings[i])
	}
	shuffled, err := findingsexport.Render(reversed, "acme-q4", "v0.4.0")
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	assertSameFiles(t, first, shuffled)
}

func assertSameFiles(t *testing.T, a, b findingsexport.Files) {
	t.Helper()
	if !bytes.Equal(a.JSON, b.JSON) {
		t.Error("two renders of one snapshot differ in JSON")
	}
	if !bytes.Equal(a.CSV, b.CSV) {
		t.Error("two renders of one snapshot differ in CSV")
	}
	if !bytes.Equal(a.SARIF, b.SARIF) {
		t.Error("two renders of one snapshot differ in SARIF")
	}
}

// TestEmptyExport covers a safe-mode run: a valid empty document, never
// nothing at all (§5).
func TestEmptyExport(t *testing.T) {
	files, err := findingsexport.Render(engagementstate.Snapshot{}, "", "v0.4.0")
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}

	for _, want := range []string{
		`"schema_version": 1`,
		`"engagement": null`,
		`"findings": []`,
		`"reported": 0`,
		`"omitted": 0`,
	} {
		if !strings.Contains(string(files.JSON), want) {
			t.Errorf("empty JSON does not contain %q:\n%s", want, files.JSON)
		}
	}

	wantCSV := "Date,Title,Severity,Url,Id,Status,Confidence,Verification,EvidenceCount\n"
	if string(files.CSV) != wantCSV {
		t.Errorf("empty CSV = %q, want the header alone", files.CSV)
	}

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []json.RawMessage `json:"results"`
			Tool    struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(files.SARIF, &log); err != nil {
		t.Fatalf("decode empty SARIF: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("empty SARIF envelope = %+v", log)
	}
	if len(log.Runs[0].Results) != 0 || len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("empty SARIF carries results or rules")
	}
}

// TestRenderedShapes pins the decisions the golden files rest on, so a
// regression names itself instead of showing a diff.
func TestRenderedShapes(t *testing.T) {
	files, err := findingsexport.Render(fixtureSnapshot(t), "acme-q4", "v0.4.0")
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	sarif := string(files.SARIF)
	csv := string(files.CSV)
	doc := string(files.JSON)

	// §2: the omission is counted in the envelope, not only on stderr.
	if !strings.Contains(doc, `"reported": 3`) || !strings.Contains(doc, `"omitted": 2`) {
		t.Errorf("counts are wrong:\n%s", doc)
	}
	// §2: risk_accepted travels in the record so a gate can exclude it.
	if !strings.Contains(doc, `"status": "risk_accepted"`) {
		t.Errorf("the risk_accepted finding is missing from the export:\n%s", doc)
	}
	// §3.2: a ref that does not resolve is carried, never dropped.
	if !strings.Contains(doc, `"kind": "unknown"`) || !strings.Contains(doc, `"ref": "host-9999"`) {
		t.Errorf("the dangling ref was not carried as unknown:\n%s", doc)
	}
	// §7.1: colliding titles take -2 in sorted-title order.
	if !strings.Contains(sarif, `"ruleId": "smb-signing-disabled"`) {
		t.Errorf("missing the base rule id:\n%s", sarif)
	}
	if !strings.Contains(sarif, `"ruleId": "smb-signing-disabled-2"`) {
		t.Errorf("a slug collision did not take -2:\n%s", sarif)
	}
	// §7.4: a detected, unverified critical is never downgraded; this one is
	// medium, so it is a warning rather than a note.
	if !strings.Contains(sarif, `"level": "warning"`) {
		t.Errorf("medium severity did not map to warning:\n%s", sarif)
	}
	// §4: no wall clock anywhere.
	for _, artifact := range []string{doc, csv, sarif} {
		if strings.Contains(artifact, `"generated_at"`) || strings.Contains(artifact, "exitCode") {
			t.Errorf("artifact carries run metadata:\n%s", artifact)
		}
	}
	// §6: one row per finding × affected endpoint, plus the header.
	if got, want := strings.Count(csv, "\n"), 1+3; got != want {
		t.Errorf("CSV has %d lines, want %d (header + 3 rows):\n%s", got, want, csv)
	}
	if !strings.Contains(csv, "10.0.0.33:445/tcp") {
		t.Errorf("CSV is missing the resolved service endpoint:\n%s", csv)
	}
	// §7.3: a scheme-less, relative-shaped location for a service.
	if !strings.Contains(sarif, `"uri": "service/10.0.0.33:445/tcp"`) {
		t.Errorf("SARIF location is not a scheme-less service path:\n%s", sarif)
	}
	// §7.5: one fingerprint, emitted twice.
	if got := strings.Count(sarif, `"styxFindingV1"`); got != 2*3 {
		t.Errorf("SARIF has %d fingerprint keys, want 2 per finding (6):\n%s", got, sarif)
	}
}

// TestReportableAndGated pins the one predicate and the gate's exclusion, so
// the artifact and the severity gate cannot drift apart.
func TestReportableAndGated(t *testing.T) {
	active := true
	base := engagementstate.Finding{
		ID: "finding-1", Title: "t", Severity: engagementstate.SeverityHigh,
		Status: engagementstate.StatusConfirmed, Confidence: engagementstate.ConfidenceHigh,
		Verification: engagementstate.VerificationUnverified, Active: active,
	}
	tests := []struct {
		name       string
		mutate     func(*engagementstate.Finding)
		wantReport bool
		wantGated  bool
	}{
		{"confirmed and unverified", func(*engagementstate.Finding) {}, true, true},
		{"detected", func(f *engagementstate.Finding) { f.Status = engagementstate.StatusDetected }, true, true},
		{"risk accepted", func(f *engagementstate.Finding) { f.Status = engagementstate.StatusRiskAccepted }, true, false},
		{"false positive", func(f *engagementstate.Finding) { f.Status = engagementstate.StatusFalsePositive }, false, false},
		{"fixed", func(f *engagementstate.Finding) { f.Status = engagementstate.StatusFixed }, false, false},
		{"refuted", func(f *engagementstate.Finding) {
			f.Verification = engagementstate.VerificationRefuted
		}, false, false},
		{"inactive", func(f *engagementstate.Finding) { f.Active = false }, false, false},
	}
	for _, tc := range tests {
		f := base
		tc.mutate(&f)
		if got := findingsexport.Reportable(f); got != tc.wantReport {
			t.Errorf("%s: Reportable() = %v, want %v", tc.name, got, tc.wantReport)
		}
		if got := findingsexport.Gated(f); got != tc.wantGated {
			t.Errorf("%s: Gated() = %v, want %v", tc.name, got, tc.wantGated)
		}
	}
}
