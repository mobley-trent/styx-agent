package parsers

import (
	"bufio"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// gobuster states its target in its banner and prints one result per line:
//
//	[+] Url:                     http://10.0.0.5:8080
//	/admin                  (Status: 301) [Size: 178]
//	Found: dev.example.com  (Status: 200)
//
// A line that reports an error or a miss ("Missed: /x (Status: 404)") is not a
// result.
var (
	// patternGobusterURL is the banner's target URL (dir and vhost modes).
	patternGobusterURL = regexp.MustCompile(`(?i)^\s*(?:\[\+\]\s*)?Url:\s*(\S+)\s*$`)
	// patternGobusterDomain is the banner's queried domain (dns mode).
	patternGobusterDomain = regexp.MustCompile(`(?i)^\s*(?:\[\+\]\s*)?Domain:\s*(\S+)\s*$`)
	// patternGobusterResult is a discovered path, in either the path-relative
	// or the expanded-URL form.
	patternGobusterResult = regexp.MustCompile(`(?i)^\s*(\S+)\s+\(Status:\s*\d{3}\)`)
	// patternGobusterFound is a discovered name (dns and vhost modes), with an
	// optional status and an optional address.
	patternGobusterFound = regexp.MustCompile(`(?i)^\s*Found:\s*(\S+)\s*(?:\(Status:\s*\d{3}\))?\s*(?:\[([0-9a-fA-F.:]+)\])?\s*$`)
	// patternGobusterMiss is a verbose miss or an error line, not a result.
	patternGobusterMiss = regexp.MustCompile(`(?i)^\s*(?:Missed|Error):`)
)

// maxDiscoveredPaths bounds the path list a dir-mode finding carries.
const maxDiscoveredPaths = 200

// gobusterName is one name gobuster discovered, with the address it printed for
// it when the run asked for addresses.
type gobusterName struct {
	// name is the discovered host or vhost name.
	name string
	// address is the address gobuster resolved it to, empty when unreported.
	address string
}

// extractGobuster reads gobuster output. Dir mode records the target as a host
// and service and collects every discovered path into one finding per host —
// a directory listing is context, not N findings (§6). Dns and vhost modes
// record each discovered name as a host, related to the target it resolves to.
//
// Recognized: the banner's `Url:` (or `Domain:`), a result line carrying
// `(Status: NNN)`, and a `Found: <name>` line. Recognized-but-empty output
// (a run that found nothing) is a success with zero counts.
func extractGobuster(in input) (Records, error) {
	scanner := bufio.NewScanner(in.file)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxArtifactBytes)

	var (
		records Records
		target  string
		port    int
		domain  string
		paths   []string
		found   []gobusterName
		results int
		misses  int
	)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if match := patternGobusterURL.FindStringSubmatch(trimmed); match != nil && target == "" {
			if host, portOfURL := targetOfURL(match[1]); host != "" {
				target, port = host, portOfURL
			}
			continue
		}
		if match := patternGobusterDomain.FindStringSubmatch(trimmed); match != nil && domain == "" {
			domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(match[1]), "."))
			continue
		}
		if patternGobusterMiss.MatchString(trimmed) {
			misses++
			continue
		}
		if match := patternGobusterFound.FindStringSubmatch(trimmed); match != nil {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(match[1]), "."))
			address := strings.TrimSpace(match[2])
			if ip, err := netip.ParseAddr(address); err == nil {
				address = ip.Unmap().String()
			}
			found = append(found, gobusterName{name: name, address: address})
			continue
		}
		if patternGobusterResult.MatchString(trimmed) {
			results++
			if len(paths) < maxDiscoveredPaths {
				paths = append(paths, collapse(trimmed))
			}
			continue
		}
	}

	if target == "" && domain == "" && len(found) == 0 && results == 0 && misses == 0 {
		return Records{}, in.unrecognized("gobuster output",
			"no banner, no result, and no discovered name")
	}

	if target != "" {
		records.Hosts = append(records.Hosts, HostRecord{Addresses: []string{target}})
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

	// Discovered names: a host each, related to the address it resolved to —
	// the address gobuster printed for it, or the target it was asked about.
	sort.Slice(found, func(i, j int) bool {
		if found[i].name != found[j].name {
			return found[i].name < found[j].name
		}
		return found[i].address < found[j].address
	})
	for _, discovery := range found {
		records.Hosts = append(records.Hosts, HostRecord{Addresses: []string{discovery.name}})
		resolvedTo := discovery.address
		if resolvedTo == "" {
			resolvedTo = target
		}
		if resolvedTo == "" || resolvedTo == discovery.name {
			continue
		}
		if discovery.address != "" {
			records.Hosts = append(records.Hosts, HostRecord{Addresses: []string{discovery.address}})
		}
		records.Edges = append(records.Edges, EdgeRecord{
			Type:       engagementstate.EdgeResolvesTo,
			From:       hostRef(discovery.name),
			To:         hostRef(resolvedTo),
			Confidence: engagementstate.ConfidenceMedium,
		})
	}

	// Dir mode: the whole listing is one finding on the host, so a re-run
	// refreshes it instead of inventing a new finding per path.
	if len(paths) > 0 {
		title := "Discovered web paths on " + target
		evidence := strings.Join(paths, "\n")
		if results > len(paths) {
			evidence += fmt.Sprintf("\n… %d more", results-len(paths))
		}
		records.Findings = append(records.Findings, FindingRecord{
			Title:      title,
			Severity:   engagementstate.SeverityInfo,
			Confidence: engagementstate.ConfidenceLow,
			Affected:   []ref{hostRef(target)},
			Evidence: []Evidence{
				{Kind: engagementstate.EvidenceCLIOutput, Ref: evidence},
				{Kind: engagementstate.EvidenceArtifact, Ref: in.artifact},
			},
		})
	}
	if target == "" && domain != "" {
		records.Warnings = append(records.Warnings,
			"a dns-mode run names its queried domain, not a host it contacted; only the discovered names were recorded")
	}
	if results > 0 && target == "" {
		records.Warnings = append(records.Warnings,
			"result paths were reported without a banner target; no host or service was recorded for them")
	}
	if misses > 0 {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("%d miss/error line(s) were not recorded (they are not results)", misses))
	}
	if err := scanner.Err(); err != nil {
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("the artifact could not be read to the end (%v); what was read was recorded", err))
	}
	return records, nil
}
