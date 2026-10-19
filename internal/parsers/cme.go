package parsers

import (
	"bufio"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// NetExec and CrackMapExec print one result per line, prefixed by the target
// columns and a marker:
//
//	SMB 10.0.0.5 445 DC01 [+] ACME\admin:hunter2 (Pwn3d!)
//	SMB 10.0.0.5 445 DC01 [-] ACME\admin:wrong STATUS_LOGON_FAILURE
//	SMB 10.0.0.5 445 DC01 [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:ACME.LOCAL) (signing:False)
//
// A per-target log may drop the columns, so a marker line without them is
// attributed to the target the last columned line named.
var (
	// patternCMELine is one line with the target columns.
	patternCMELine = regexp.MustCompile(`^\s*([A-Za-z0-9]+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,5})\s+(\S+)\s+(\[\+\]|\[-\]|\[!\]|\[\*\])\s*(.*)$`)
	// patternCMEMarker is one line without them.
	patternCMEMarker = regexp.MustCompile(`^\s*(\[\+\]|\[-\]|\[!\]|\[\*\])\s*(.+)$`)
	// patternCMETarget is the artifact's own record of a target, for the
	// pending-parse sniff.
	patternCMETarget = patternCMELine
	// patternCMESigning reports the SMB signing state in the OS banner.
	patternCMESigning = regexp.MustCompile(`(?i)\(signing:(true|false)\)`)
	// patternCMEName is the machine name in the OS banner.
	patternCMEName = regexp.MustCompile(`(?i)\(name:([^)]+)\)`)
)

// extractCME reads CrackMapExec / NetExec output. It records the hosts and
// services the run touched, the credentials that worked, the footholds they
// gave (Pwn3d! marks an administrative one), and one finding per positive
// module result.
//
// Recognized: a line carrying the target columns and a `[+]` / `[-]` / `[!]` /
// `[*]` marker, or a bare marker line under the last target. A `[+]` message of
// the form `<DOMAIN>\<user>:<secret>` is a credential, with `(Pwn3d!)` marking
// it administrative; `[-]` lines are failed attempts, which are not
// observations. The OS banner's `(signing:False)` becomes an SMB signing
// finding. Any other `[+]` result is recorded at `info`: the output states no
// severity, and inventing one would be worse than saying so.
func extractCME(in input) (Records, error) {
	scanner := bufio.NewScanner(in.file)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxArtifactBytes)

	var (
		records   Records
		host      string
		port      int
		hostname  string
		os        string
		signing   string
		targeted  bool
		positives int
	)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		marker := ""
		message := ""
		if match := patternCMELine.FindStringSubmatch(trimmed); match != nil {
			if ip, err := netip.ParseAddr(match[2]); err == nil {
				host = ip.Unmap().String()
			} else {
				host = match[2]
			}
			if value, err := strconv.Atoi(match[3]); err == nil && value > 0 && value <= 65535 {
				port = value
			}
			if hostname == "" {
				hostname = strings.TrimSpace(match[4])
			}
			targeted = true
			marker, message = match[5], strings.TrimSpace(match[6])
		} else if match := patternCMEMarker.FindStringSubmatch(trimmed); match != nil {
			if !targeted {
				records.Skipped = append(records.Skipped, Skipped{
					Record: collapse(trimmed),
					Reason: "no target columns and no target seen yet: the line cannot be attributed",
				})
				continue
			}
			marker, message = match[1], strings.TrimSpace(match[2])
		} else {
			continue
		}

		switch marker {
		case "[-]":
			// A failed attempt is not an observation.
			continue
		case "[*]":
			if nameMatch := patternCMEName.FindStringSubmatch(message); nameMatch != nil {
				hostname = strings.TrimSpace(nameMatch[1])
			}
			if os == "" {
				os = bannerOS(message)
			}
			if signMatch := patternCMESigning.FindStringSubmatch(message); signMatch != nil {
				signing = strings.ToLower(signMatch[1])
			}
			continue
		case "[!]":
			continue
		}

		// [+] : a positive result.
		principal, secret, pwned, isCredential := cmeCredential(message)
		if isCredential {
			records.Credentials = append(records.Credentials, CredentialRecord{
				Type:      engagementstate.CredentialPassword,
				Principal: principal,
				Secret:    secret,
			})
			credential := credentialRef(engagementstate.CredentialPassword, principal, secret)
			records.Edges = append(records.Edges, EdgeRecord{
				Type:       engagementstate.EdgeValidFor,
				From:       credential,
				To:         hostRef(host),
				Confidence: engagementstate.ConfidenceHigh,
			})
			level := engagementstate.LevelUser
			if pwned {
				level = engagementstate.LevelAdmin
				records.Edges = append(records.Edges, EdgeRecord{
					Type:       engagementstate.EdgeAdminOf,
					From:       credential,
					To:         hostRef(host),
					Confidence: engagementstate.ConfidenceHigh,
				})
			}
			records.Edges = append(records.Edges, EdgeRecord{
				Type:       engagementstate.EdgePivotTo,
				From:       accessRef(credential, hostRef(host)),
				To:         hostRef(host),
				Confidence: engagementstate.ConfidenceHigh,
			})
			records.Accesses = append(records.Accesses, AccessRecord{
				Principal: credential,
				Target:    hostRef(host),
				Level:     level,
			})
			continue
		}

		positives++
		severity := engagementstate.SeverityInfo
		confidence := engagementstate.ConfidenceMedium
		records.Findings = append(records.Findings, FindingRecord{
			Title:      message,
			Severity:   severity,
			Confidence: confidence,
			Affected:   []ref{hostRef(host)},
			Evidence: []Evidence{
				{Kind: engagementstate.EvidenceCLIOutput, Ref: collapse(trimmed)},
				{Kind: engagementstate.EvidenceArtifact, Ref: in.artifact},
			},
		})
	}

	if !targeted {
		return Records{}, in.unrecognized("CrackMapExec or NetExec output",
			"no line carries the protocol/address/port/hostname columns")
	}

	records.Hosts = append(records.Hosts, HostRecord{Addresses: []string{host}, Hostname: hostname, OS: os})
	if port > 0 {
		records.Services = append(records.Services, ServiceRecord{
			Host:  host,
			Port:  port,
			Proto: engagementstate.ProtoTCP,
		})
		records.Edges = append(records.Edges, EdgeRecord{
			Type:       engagementstate.EdgeRunsOn,
			From:       serviceRef(host, port, engagementstate.ProtoTCP),
			To:         hostRef(host),
			Confidence: engagementstate.ConfidenceHigh,
		})
	}
	if signing == "false" {
		records.Findings = append(records.Findings, FindingRecord{
			Title:      "SMB signing disabled",
			Severity:   engagementstate.SeverityMedium,
			Confidence: engagementstate.ConfidenceHigh,
			Affected:   []ref{hostRef(host)},
			Evidence: []Evidence{
				{Kind: engagementstate.EvidenceCLIOutput, Ref: fmt.Sprintf("NetExec reported (signing:False) for %s", host)},
				{Kind: engagementstate.EvidenceArtifact, Ref: in.artifact},
			},
		})
	}
	if positives > 0 {
		records.Warnings = append(records.Warnings, fmt.Sprintf(
			"%d positive module result(s) were recorded at info severity: the output states none", positives))
	}
	if len(records.Credentials) == 0 {
		records.Warnings = append(records.Warnings,
			"no working credential is reported in the artifact (a credential needs both its principal and its secret)")
	}
	if err := scanner.Err(); err != nil {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("the artifact could not be read to the end (%v); what was read was recorded", err))
	}
	return records, nil
}

// cmeCredential reads a `[+]` message as a working credential. The message
// format is `<DOMAIN>\<user>:<secret>`, optionally suffixed `(Pwn3d!)`.
func cmeCredential(message string) (principal, secret string, pwned, ok bool) {
	message = strings.TrimSpace(message)
	lower := strings.ToLower(message)
	if strings.HasSuffix(lower, "(pwn3d!)") {
		pwned = true
		message = strings.TrimSpace(message[:len(message)-len("(Pwn3d!)")])
	}
	left, right, found := strings.Cut(message, ":")
	if !found {
		return "", "", false, false
	}
	principal = strings.TrimSpace(left)
	secret = strings.TrimSpace(right)
	if principal == "" || secret == "" || strings.ContainsAny(principal, " \t") {
		// A blank secret is still an observation of a valid login, but a
		// credential entity requires its secret; the warning says so.
		return "", "", false, false
	}
	for _, r := range principal {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune(`\-_.@$`, r)
		if !ok {
			return "", "", false, false
		}
	}
	return principal, secret, pwned, true
}

// bannerOS is the operating system a `[*]` banner states, up to its first
// parenthesized detail ("Windows Server 2019 Build 17763 x64 (name:DC01) …").
func bannerOS(message string) string {
	if cut, _, ok := strings.Cut(message, "("); ok {
		return strings.TrimSpace(cut)
	}
	return strings.TrimSpace(message)
}
