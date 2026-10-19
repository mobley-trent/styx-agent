package parsers

import (
	"bufio"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// sqlmap's log is text: its console formatter writes "\r[HH:MM:SS] [LEVEL]
// message" (lib/core/log.py), and its per-target `log` holds the result blocks
// the dumper writes (lib/core/dump.py) — an injection summary, a user list, and
// per-user password hashes. These are the patterns the extractor recognizes;
// anything else is a skipped record, never a guess (§7).
var (
	// patternSQLMapInjectable is the report that a parameter is injectable.
	// sqlmap has two wordings: "is '…' injectable" (a confirmed technique) and
	// "appears to be '…' injectable" (heuristic branch taken). Both are the
	// finding; the technique text is the finding's detail.
	patternSQLMapInjectable = regexp.MustCompile(`(?i)\b(GET|POST|COOKIE|URI|HEADER|User-Agent|Referer)\s+parameter\s+'([^']+)'\s+(?:is|appears to be)\s+'([^']*)'\s+injectable`)
	// patternSQLMapHash is one dumped password hash.
	patternSQLMapHash = regexp.MustCompile(`(?i)^\s*password hash:\s*(\S*)\s*$`)
	// patternSQLMapHashUser opens a per-user hash block: "[*] root [2]:".
	patternSQLMapHashUser = regexp.MustCompile(`^\s*\[\*\]\s+(.+?)\s*\[\d+\]:\s*$`)
	// patternSQLMapUser is one listed DBMS user: "[*] 'root'@'localhost'".
	patternSQLMapUser = regexp.MustCompile(`^\s*\[\*\]\s+'?([^'\s@]+)'?@'?([^'\s]+)'?\s*$`)
	// patternSQLMapDBA reports the queried account's privilege.
	patternSQLMapDBA = regexp.MustCompile(`(?i)current user is DBA:\s*(true|1)`)
	// patternSQLMapCurrentUser names the account sqlmap queried as.
	patternSQLMapCurrentUser = regexp.MustCompile(`(?i)current user:\s*'?([^'\s]+)'?`)
	// patternSQLMapTarget is sqlmap's own record of the URL under test
	// (lib/controller/controller.py: "testing URL '<url>'").
	patternSQLMapTarget = regexp.MustCompile(`(?i)(?:testing URL|target URL|URI)\s*[:=]?\s*'?(https?://\S+?)'?\s*$`)
	// patternSQLMapArtifactTarget is the artifact-naming convention the
	// harness routes scanner output under: `.styx/out/sqlmap-<target>.log`.
	patternSQLMapArtifactTarget = regexp.MustCompile(`(?i)^sqlmap[-_](.+)$`)
)

// extractSQLMap reads a sqlmap log. Every injectable parameter becomes one
// high-severity finding with the technique as its detail, dumped password
// hashes become credentials, and a DBA report becomes an admin foothold on the
// target reached through the injection it ran.
//
// The host is taken, in order, from sqlmap's own target line, from the first
// URL the log mentions, and — because a per-target log lives in
// `output/<host>/log` and often repeats neither — from the artifact name the
// harness routes output under (`sqlmap-<target>.log`). A log that names no
// target at all is refused: a finding cannot hang off a host the artifact never
// identified.
func extractSQLMap(in input) (Records, error) {
	scanner := bufio.NewScanner(in.file)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxArtifactBytes)

	var (
		records     Records
		target      string
		port        int
		findings    int
		firstInject ref
		currentUser string
		hashUser    string
		listedUsers int
	)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if target == "" {
			if match := patternSQLMapTarget.FindStringSubmatch(trimmed); match != nil {
				if host, portOfURL := targetOfURL(match[1]); host != "" {
					target, port = host, portOfURL
				}
			}
		}
		if match := patternSQLMapCurrentUser.FindStringSubmatch(trimmed); match != nil {
			currentUser = strings.TrimSpace(match[1])
		}
		if match := patternSQLMapHashUser.FindStringSubmatch(trimmed); match != nil {
			hashUser = strings.TrimSpace(match[1])
			continue
		}
		if match := patternSQLMapHash.FindStringSubmatch(trimmed); match != nil {
			hash := strings.TrimSpace(match[1])
			if hash == "" || strings.EqualFold(hash, "null") {
				records.Skipped = append(records.Skipped, Skipped{
					Record: collapse(trimmed),
					Reason: "the hash is empty or NULL: there is no secret to record",
				})
				continue
			}
			if hashUser == "" {
				records.Skipped = append(records.Skipped, Skipped{
					Record: collapse(trimmed),
					Reason: "a password hash with no user block above it: the credential needs its principal",
				})
				continue
			}
			records.Credentials = append(records.Credentials, CredentialRecord{
				Type:      engagementstate.CredentialHash,
				Principal: hashUser,
				Secret:    hash,
			})
			continue
		}
		if match := patternSQLMapUser.FindStringSubmatch(trimmed); match != nil {
			listedUsers++
			continue
		}
		if match := patternSQLMapInjectable.FindStringSubmatch(trimmed); match != nil {
			if target == "" {
				records.Skipped = append(records.Skipped, Skipped{
					Record: collapse(trimmed),
					Reason: "no target host is named anywhere in the artifact",
				})
				continue
			}
			method, parameter := match[1], match[2]
			// One finding per injectable parameter (§6), whatever technique
			// proved it: the technique is the evidence, not a second finding.
			title := fmt.Sprintf("SQL injection in %s parameter '%s'", strings.ToUpper(method), parameter)
			finding := FindingRecord{
				Title:      title,
				Severity:   engagementstate.SeverityHigh,
				Confidence: engagementstate.ConfidenceHigh,
				Affected:   []ref{hostRef(target)},
				Evidence: []Evidence{
					{Kind: engagementstate.EvidenceCLIOutput, Ref: collapse(trimmed)},
					{Kind: engagementstate.EvidenceArtifact, Ref: in.artifact},
				},
			}
			records.Findings = append(records.Findings, finding)
			if firstInject.kind != refFinding {
				firstInject = findingRef(finding.Title, finding.Affected...)
			}
			findings++
			continue
		}
		if patternSQLMapDBA.MatchString(trimmed) {
			if currentUser == "" {
				records.Skipped = append(records.Skipped, Skipped{
					Record: collapse(trimmed),
					Reason: "the DBA report names no current user in the artifact: an access record needs its principal",
				})
				continue
			}
			if target == "" {
				records.Skipped = append(records.Skipped, Skipped{
					Record: collapse(trimmed),
					Reason: "no target host is named anywhere in the artifact",
				})
				continue
			}
			access := AccessRecord{
				Principal: accountRef(currentUser),
				Target:    hostRef(target),
				Level:     engagementstate.LevelAdmin,
			}
			if firstInject.kind == refFinding {
				access.Via = firstInject
			}
			records.Accesses = append(records.Accesses, access)
			continue
		}
	}

	if target == "" {
		target, port = targetFromArtifactName(in.artifact)
	}
	if target == "" {
		return Records{}, in.unrecognized("a sqlmap log that names its target",
			"no target URL, no SQL injection report, and the artifact name carries no target")
	}

	records.Hosts = append(records.Hosts, HostRecord{Addresses: []string{target}})
	if port > 0 {
		records.Services = append(records.Services, ServiceRecord{
			Host:  target,
			Port:  port,
			Proto: engagementstate.ProtoTCP,
		})
		records.Edges = append(records.Edges, EdgeRecord{
			Type:       engagementstate.EdgeRunsOn,
			From:       serviceRef(target, port, engagementstate.ProtoTCP),
			To:         hostRef(target),
			Confidence: engagementstate.ConfidenceHigh,
		})
	}
	// A dumped DBMS account came from the target and works on it (§6).
	for _, credential := range records.Credentials {
		from := credentialRef(credential.Type, credential.Principal, credential.Secret)
		records.Edges = append(records.Edges,
			EdgeRecord{
				Type:       engagementstate.EdgeCredentialFrom,
				From:       from,
				To:         hostRef(target),
				Confidence: engagementstate.ConfidenceHigh,
			},
			EdgeRecord{
				Type:       engagementstate.EdgeValidFor,
				From:       from,
				To:         hostRef(target),
				Confidence: engagementstate.ConfidenceHigh,
			},
		)
	}
	if findings == 0 {
		records.Warnings = append(records.Warnings,
			"the artifact reports no injectable parameter: nothing was recorded as a finding")
	}
	if listedUsers > 0 {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("%d database user(s) were listed without secrets; a credential needs its secret, so they were not recorded", listedUsers))
	}
	if err := scanner.Err(); err != nil {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("the artifact could not be read to the end (%v); what was read was recorded", err))
	}
	return records, nil
}

// targetOfURL pulls the host and any explicit port out of a target URL.
func targetOfURL(raw string) (string, int) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", 0
	}
	host := parsed.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	port := 0
	if parsed.Port() != "" {
		if value, err := strconv.Atoi(parsed.Port()); err == nil {
			port = value
		}
	}
	if port == 0 {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	return host, port
}

// targetFromArtifactName reads a target out of the artifact-naming convention
// the harness routes scanner output under: `.styx/out/sqlmap-<target>.log`.
func targetFromArtifactName(artifact string) (string, int) {
	base := filepath.Base(filepath.FromSlash(artifact))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	match := patternSQLMapArtifactTarget.FindStringSubmatch(base)
	if match == nil {
		return "", 0
	}
	candidate := strings.TrimSpace(match[1])
	if ip, err := netip.ParseAddr(candidate); err == nil {
		return ip.Unmap().String(), 0
	}
	for _, r := range candidate {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-' || r == '_'
		if !ok {
			return "", 0
		}
	}
	if candidate == "" || strings.HasPrefix(candidate, ".") || strings.Contains(candidate, "..") {
		return "", 0
	}
	return candidate, 0
}
