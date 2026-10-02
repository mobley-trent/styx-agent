package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/mobley-trent/styx-agent/internal/policy"
)

// Fetcher performs a harness-side URL fetch (§5.1). It is deliberately a seam:
// `agent` knows only that web_fetch delegates to a harness-side fetcher, never
// how the network is reached. The production implementation (internal/netfetch)
// re-resolves the destination and refuses anything outside the engagement's
// pinned scope; tests substitute a recording fake and stay offline.
type Fetcher interface {
	// Fetch retrieves a URL and returns its body as text.
	Fetch(ctx context.Context, rawURL string) (string, error)
}

// LogFetcher performs a read-only remote log fetch (§5.1). The command has
// already been validated against the read-only allowlist (see
// validateReadOnlyCommand) before it reaches the fetcher; the fetcher is the
// transport, not the safety boundary.
type LogFetcher interface {
	// Logs runs a read-only command on a remote host and returns its output.
	Logs(ctx context.Context, target string, command []string) (string, error)
}

// webFetchSchema is the `web_fetch` descriptor's JSON Schema (strict mode:
// every property is declared and additionalProperties is false).
const webFetchSchema = `{
  "type": "object",
  "properties": {
    "url": {
      "type": "string",
      "description": "Absolute http(s) URL to fetch. The harness resolves the destination and refuses targets outside the engagement scope."
    }
  },
  "required": ["url"],
  "additionalProperties": false
}`

// sshLogsSchema is the `ssh_logs` descriptor's JSON Schema. The command must
// name a read-only tool from the harness allowlist; write-capable commands are
// refused before they run.
const sshLogsSchema = `{
  "type": "object",
  "properties": {
    "target": {
      "type": "string",
      "description": "Remote host to read logs from, e.g. \"web01.acme.example\" or \"user@web01.acme.example\". Scope-checked."
    },
    "command": {
      "type": "string",
      "description": "A single read-only command from the allowlist (cat, tail, grep, zgrep, zcat, wc, ...), e.g. \"tail -n 200 /var/log/syslog\". Shell metacharacters and write-capable programs are refused."
    }
  },
  "required": ["target", "command"],
  "additionalProperties": false
}`

// WebFetchTool is the §5.1 `web_fetch` tool: a harness-side URL fetch whose
// destination is scope-checked like any other network call. It carries the
// URL's host as its scope target, so the policy engine resolves in-scope
// fetches to auto-allow (engagement mode) and out-of-scope fetches to a prompt
// (§6.2). The fetcher repeats the destination check against the pinned IPs at
// connect time (§7.2: DNS-rebinding defense).
func WebFetchTool(fetcher Fetcher) Tool {
	return Tool{
		Name:        "web_fetch",
		Description: "Fetch an absolute http(s) URL harness-side. The destination is checked against the engagement scope; out-of-scope targets are held for the operator.",
		Parameters:  json.RawMessage(webFetchSchema),
		Targets: func(args map[string]any) []policy.Target {
			raw, _ := args["url"].(string)
			host := urlHost(raw)
			if host == "" {
				return nil
			}
			return []policy.Target{{Addr: host}}
		},
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			raw, err := stringArg(args, "url")
			if err != nil {
				return "", err
			}
			if fetcher == nil {
				return "", errors.New("no harness-side fetcher is configured for web_fetch")
			}
			return fetcher.Fetch(ctx, raw)
		},
	}
}

// SSHLogsTool is the §5.1 `ssh_logs` tool: a read-only remote log fetch. Its
// handler refuses any command outside the harness's read-only allowlist before
// the transport is touched, so the restriction does not depend on the model
// choosing safe commands. Its target is scope-checked like any network call.
func SSHLogsTool(fetcher LogFetcher) Tool {
	return Tool{
		Name:        "ssh_logs",
		Description: "Read logs from a remote host over SSH. Only read-only commands from the harness allowlist are accepted; write-capable commands and shell metacharacters are refused. The host is checked against the engagement scope.",
		Parameters:  json.RawMessage(sshLogsSchema),
		Targets: func(args map[string]any) []policy.Target {
			raw, _ := args["target"].(string)
			host := sshTargetHost(raw)
			if host == "" {
				return nil
			}
			return []policy.Target{{Addr: host}}
		},
		Handler: func(ctx context.Context, args map[string]any) (string, error) {
			target, err := stringArg(args, "target")
			if err != nil {
				return "", err
			}
			command, err := stringArg(args, "command")
			if err != nil {
				return "", err
			}
			argv, err := validateReadOnlyCommand(command)
			if err != nil {
				return "", err
			}
			if fetcher == nil {
				return "", errors.New("no remote log fetcher is configured for ssh_logs")
			}
			return fetcher.Logs(ctx, target, argv)
		},
	}
}

// readOnlyPrograms is the ssh_logs allowlist: tools that only read. Write- or
// state-changing programs (rm, mv, sed, awk, tee, journalctl, dmesg, sort -o)
// are deliberately absent — a read-only log fetch must not be able to mutate
// the target, even under an operator prompt.
var readOnlyPrograms = map[string]bool{
	"cat":     true,
	"head":    true,
	"tail":    true,
	"grep":    true,
	"egrep":   true,
	"fgrep":   true,
	"zgrep":   true,
	"zegrep":  true,
	"zfgrep":  true,
	"zcat":    true,
	"zless":   true,
	"zmore":   true,
	"wc":      true,
	"cut":     true,
	"uniq":    true,
	"strings": true,
	"stat":    true,
	"file":    true,
	"ls":      true,
	"od":      true,
	"xxd":     true,
	"hexdump": true,
	"last":    true,
	"lastlog": true,
	"who":     true,
	"w":       true,
}

// followFlags are streaming options that would never return, so a log read
// must not use them.
var followFlags = map[string]bool{"-f": true, "--follow": true, "-F": true, "--follow=name": true}

// validateReadOnlyCommand parses and vets an ssh_logs command against the
// read-only allowlist. It returns the command's argv for the transport. A
// command is refused unless its program is allowlisted, it carries no shell
// metacharacters (so the remote login shell cannot chain or redirect), and it
// does not request a follow/stream that would hang the harness.
func validateReadOnlyCommand(command string) ([]string, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil, errors.New("ssh_logs: command is required")
	}
	if strings.ContainsAny(trimmed, "\n\r\x00") {
		return nil, errors.New("ssh_logs: the command must be a single line")
	}
	argv := strings.Fields(trimmed)
	if len(argv) == 0 {
		return nil, errors.New("ssh_logs: command is required")
	}
	program := argv[0]
	if !readOnlyPrograms[program] {
		return nil, fmt.Errorf("ssh_logs: %q is not on the read-only allowlist (cat, head, tail, grep, zgrep, zcat, wc, ...)", program)
	}
	if strings.ContainsAny(trimmed, `;|&$<>(){}`+"`\\") {
		return nil, errors.New("ssh_logs: shell metacharacters are refused; send one plain read-only command")
	}
	for _, arg := range argv[1:] {
		if followFlags[arg] {
			return nil, fmt.Errorf("ssh_logs: %s %s would stream indefinitely; read a bounded range instead", program, arg)
		}
	}
	return argv, nil
}

// urlHost extracts the host from an absolute URL, empty when the URL does not
// parse or has no host. The port is dropped: scope matches on destination, not
// service.
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return sshTargetHost(u.Host)
}

// sshTargetHost strips an SSH user and port from a target ("user@host:22" ->
// "host"), tolerating bracketed IPv6 forms.
func sshTargetHost(raw string) string {
	s := strings.TrimSpace(raw)
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			return s[1:end]
		}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}
