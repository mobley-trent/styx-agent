package parsers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
)

// maxEvidenceExcerpt bounds one inline evidence excerpt. The artifact is the
// full record; the excerpt is for the model's eyes, and a whole HTTP response
// body would crowd out the receipt.
const maxEvidenceExcerpt = 2000

// nucleiResult is one line of nuclei output (`-jsonl`), or one element of its
// `-je` array (§6, `nuclei_parse`).
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	Scheme     string `json:"scheme"`
	URL        string `json:"url"`
	MatchedAt  string `json:"matched-at"`
	IP         string `json:"ip"`
	Request    string `json:"request"`
	Response   string `json:"response"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

// extractNuclei reads nuclei JSON Lines output. Every template match becomes
// one finding on the host it matched, with the request/response excerpt that
// proves it; the matched port becomes a service.
//
// Recognized: an object per line (`-jsonl`) or one JSON array of objects
// (`-je`), with the `template-id`, `info.name`, `info.severity`, `host`,
// `port`, `scheme`, `url`, `matched-at`, `ip`, `request`, and `response`
// fields. A severity nuclei reports as `unknown` is recorded as `info`, with a
// warning: the finding is real, its severity is simply not stated.
func extractNuclei(in input) (Records, error) {
	scanner := bufio.NewScanner(in.file)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxArtifactBytes)

	var (
		records Records
		results []nucleiResult
		// sawContent distinguishes an artifact with nothing in it — a run
		// that found nothing, which is a valid empty result — from one whose
		// lines are simply not nuclei output, which is a refusal.
		sawContent bool
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		sawContent = true
		if strings.HasPrefix(line, "[") {
			// `-je`: one JSON array for the whole run.
			results = append(results, decodeNucleiArray(line, &records)...)
			continue
		}
		if !strings.HasPrefix(line, "{") {
			records.Skipped = append(records.Skipped, Skipped{
				Record: truncateLine(line),
				Reason: "not a JSON object: nuclei -jsonl writes one object per line",
			})
			continue
		}
		var result nucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			records.Skipped = append(records.Skipped, Skipped{
				Record: truncateLine(line),
				Reason: fmt.Sprintf("malformed JSON object: %v", err),
			})
			continue
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		if len(results) == 0 {
			return Records{}, in.unrecognized("nuclei JSON Lines output (nuclei -jsonl)", err.Error())
		}
		records.Warnings = append(records.Warnings,
			fmt.Sprintf("the artifact could not be read to the end (%v); what was read was recorded", err))
	}
	if len(results) == 0 && sawContent {
		return Records{}, in.unrecognized("nuclei JSON Lines output (nuclei -jsonl)",
			"the artifact has lines but none is a JSON object")
	}

	for _, result := range results {
		records = recordNucleiResult(records, result, in)
	}
	return records, nil
}

// decodeNucleiArray reads one `-je` array element by element, so a large run
// does not have to fit in memory at once.
func decodeNucleiArray(line string, records *Records) []nucleiResult {
	decoder := json.NewDecoder(strings.NewReader(line))
	token, err := decoder.Token()
	if err != nil {
		return nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return nil
	}
	var out []nucleiResult
	for decoder.More() {
		var result nucleiResult
		if err := decoder.Decode(&result); err != nil {
			records.Skipped = append(records.Skipped, Skipped{
				Record: "<array element>",
				Reason: fmt.Sprintf("malformed JSON object: %v", err),
			})
			break
		}
		out = append(out, result)
	}
	return out
}

// recordNucleiResult folds one match into the records: its host and service,
// and the finding the template raised on it.
func recordNucleiResult(records Records, result nucleiResult, in input) Records {
	title := strings.TrimSpace(result.Info.Name)
	if title == "" {
		title = strings.TrimSpace(result.TemplateID)
	}
	if title == "" {
		records.Skipped = append(records.Skipped, Skipped{
			Record: truncateLine(result.MatchedAt + " " + result.Host),
			Reason: "no template name or id: the match cannot be titled",
		})
		return records
	}

	target := nucleiTarget(result)
	if target == "" {
		records.Skipped = append(records.Skipped, Skipped{
			Record: title,
			Reason: "no host or IP in the match: a finding hangs off the host it was found on",
		})
		return records
	}
	port := nucleiPort(result)

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
			Confidence: engagementstate.ConfidenceMedium,
		})
	}

	severity := engagementstate.Severity(strings.ToLower(strings.TrimSpace(result.Info.Severity)))
	switch severity {
	case engagementstate.SeverityLow, engagementstate.SeverityMedium,
		engagementstate.SeverityHigh, engagementstate.SeverityCritical:
	case engagementstate.SeverityInfo, "unknown", "":
		severity = engagementstate.SeverityInfo
		if result.Info.Severity == "" || strings.EqualFold(result.Info.Severity, "unknown") {
			records.Warnings = append(records.Warnings, fmt.Sprintf(
				"template %s reports severity %q; the finding was recorded as info",
				result.TemplateID, result.Info.Severity))
		}
	default:
		records.Skipped = append(records.Skipped, Skipped{
			Record: title,
			Reason: fmt.Sprintf("nuclei severity %q is not one of info/low/medium/high/critical", result.Info.Severity),
		})
		return records
	}

	evidence := []Evidence{{Kind: engagementstate.EvidenceArtifact, Ref: in.artifact}}
	if excerpt := httpExcerpt(result.Request, result.Response); excerpt != "" {
		evidence = append([]Evidence{{Kind: engagementstate.EvidenceHTTPResponse, Ref: excerpt}}, evidence...)
	}
	records.Findings = append(records.Findings, FindingRecord{
		Title:      title,
		Severity:   severity,
		Confidence: engagementstate.ConfidenceMedium,
		Affected:   []ref{hostRef(target)},
		Evidence:   evidence,
	})
	return records
}

// nucleiTarget is the host a match landed on: the resolved IP when nuclei
// reports one, else the host of the matched URL.
func nucleiTarget(result nucleiResult) string {
	if ip, err := netip.ParseAddr(strings.TrimSpace(result.IP)); err == nil {
		return ip.Unmap().String()
	}
	for _, candidate := range []string{result.MatchedAt, result.URL, result.Host} {
		if host := hostOfURL(candidate); host != "" {
			return host
		}
	}
	// A network template names its target as a bare host:port in `host`.
	if host := strings.TrimSpace(result.Host); host != "" {
		if !strings.Contains(host, " ") {
			return host
		}
	}
	return ""
}

// nucleiPort is the port a match landed on: the reported port, else the URL's,
// else the scheme's default.
func nucleiPort(result nucleiResult) int {
	if port, err := strconv.Atoi(strings.TrimSpace(result.Port)); err == nil && port > 0 && port <= 65535 {
		return port
	}
	if parsed, err := url.Parse(result.MatchedAt); err == nil && parsed.Port() != "" {
		if port, err := strconv.Atoi(parsed.Port()); err == nil {
			return port
		}
	}
	if parsed, err := url.Parse(result.URL); err == nil && parsed.Port() != "" {
		if port, err := strconv.Atoi(parsed.Port()); err == nil {
			return port
		}
	}
	switch strings.ToLower(strings.TrimSpace(result.Scheme)) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// hostOfURL pulls the host out of a URL, tolerating a bare host.
func hostOfURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if !strings.ContainsAny(raw, "/: ") {
		return raw
	}
	return ""
}

// httpExcerpt renders the request and response nuclei captured, bounded.
func httpExcerpt(request, response string) string {
	parts := make([]string, 0, 2)
	for _, part := range []string{request, response} {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	excerpt := strings.Join(parts, "\n---\n")
	if len(excerpt) > maxEvidenceExcerpt {
		excerpt = excerpt[:maxEvidenceExcerpt] + "\n[excerpt truncated]"
	}
	return excerpt
}

// truncateLine shortens a line for a skipped-record report.
func truncateLine(line string) string {
	line = collapse(line)
	if len(line) > 160 {
		return line[:160] + "…"
	}
	return line
}
