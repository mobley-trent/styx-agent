package engagementstate

import (
	"fmt"
	"slices"
	"strings"
)

// Digest caps (§8): the digest is a compact view, and overflow truncates with
// a pointer to `state_query` rather than growing the turn's prompt.
const (
	// digestMaxFindings is how many open findings the digest lists.
	digestMaxFindings = 6
	// digestMaxBytes bounds the digest body.
	digestMaxBytes = 1200
)

// Digest renders the state digest (§8) and reports whether one is due. A
// digest is due when state changed since the previous one, and always when
// forced — which is how the loop re-appends one after compaction evicts the
// digest a conversation already carried, and how activation announces the
// store the first time.
//
// Reading a digest consumes it: the next call reports nothing until state
// changes again.
func (s *Store) Digest(force bool) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	counts := s.doc.digestCounts()
	if !force && s.lastDigest == s.doc.Revision {
		return "", false
	}
	body := s.doc.renderDigest(counts, s.lastCounts, s.writable, s.holder)
	s.lastDigest = s.doc.Revision
	s.lastCounts = counts
	return body, true
}

// digestCounts folds the document into the digest's counters: active entities
// by kind, active findings, open ones, and unverified ones.
func (d *document) digestCounts() map[string]int {
	counts := map[string]int{}
	for _, e := range d.Entities {
		if e.Active {
			counts[string(e.Kind)]++
		}
	}
	for _, f := range d.Findings {
		if !f.Active {
			continue
		}
		counts[string(KindFinding)]++
		if f.Status.IsOpen() {
			counts["findings_open"]++
		}
		if f.Verification == VerificationUnverified {
			counts["findings_unverified"]++
		}
	}
	return counts
}

// openFindings returns the active, still-open findings, most severe first, then
// most recently seen, then by id — a stable order for a stable digest.
func (d *document) openFindings() []Finding {
	var out []Finding
	for _, f := range d.Findings {
		if f.Active && f.Status.IsOpen() {
			out = append(out, f)
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return rb - ra
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			if a.LastSeen.After(b.LastSeen) {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// renderDigest renders one digest body. Empty state still produces a body: at
// activation the model should know the store exists and holds nothing yet.
func (d *document) renderDigest(counts, previous map[string]int, writable bool, holder string) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("engagement state — revision %d", d.Revision))

	countLine := strings.Join([]string{
		fmt.Sprintf("hosts %d", counts[string(KindHost)]),
		fmt.Sprintf("services %d", counts[string(KindService)]),
		fmt.Sprintf("credentials %d", counts[string(KindCredential)]),
		fmt.Sprintf("access %d", counts[string(KindAccess)]),
		fmt.Sprintf("segments %d", counts[string(KindSegment)]),
	}, " · ")
	lines = append(lines, countLine)

	findings := counts[string(KindFinding)]
	if findings == 0 {
		lines = append(lines, "findings 0")
	} else {
		lines = append(lines, fmt.Sprintf("findings %d (%d open, %d unverified)",
			findings, counts["findings_open"], counts["findings_unverified"]))
	}

	if findings == 0 && len(d.Entities) == 0 {
		lines = append(lines, "no observations recorded yet")
	}

	open := d.openFindings()
	shown := open
	if len(shown) > digestMaxFindings {
		shown = shown[:digestMaxFindings]
	}
	for _, f := range shown {
		lines = append(lines, fmt.Sprintf("- %s · %s", f.Severity, f.Title))
	}
	if more := len(open) - len(shown); more > 0 {
		lines = append(lines, fmt.Sprintf("… %d more open finding(s); use state_query", more))
	}

	lines = append(lines, deltaLine(counts, previous, d.Revision))
	if !writable {
		// A read-only store is not silent about it: every write this session
		// attempts would fail, and the model should know before it tries.
		lines = append(lines, "writes unavailable: engagement state is locked by "+holder)
	}
	if len(open) > 0 || len(d.Entities) > 0 {
		lines = append(lines, "state_query for detail")
	}
	return capDigest(lines)
}

// deltaLine renders the per-kind deltas since the previous digest.
func deltaLine(counts, previous map[string]int, revision int) string {
	if previous == nil {
		return "first digest of this engagement"
	}
	order := []string{
		string(KindHost), string(KindService), string(KindCredential),
		string(KindAccess), string(KindSegment), string(KindFinding),
		"findings_open", "findings_unverified",
	}
	var parts []string
	for _, key := range order {
		if delta := counts[key] - previous[key]; delta > 0 {
			parts = append(parts, fmt.Sprintf("+%d %s", delta, strings.ReplaceAll(key, "_", " ")))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("no new observations since the last digest (revision %d)", revision)
	}
	return "new since the last digest: " + strings.Join(parts, ", ")
}

// capDigest bounds a digest body, replacing anything past the cap with an
// explicit elision line (§8: overflow truncates with a state_query pointer).
func capDigest(lines []string) string {
	var b strings.Builder
	for _, line := range lines {
		if b.Len()+len(line)+1 > digestMaxBytes {
			b.WriteString("… digest truncated; use state_query\n")
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}
