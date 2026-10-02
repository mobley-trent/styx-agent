package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// recordingFetcher is a hermetic Fetcher: it records the URLs it was asked
// for and returns canned output.
type recordingFetcher struct {
	urls []string
	body string
	err  error
}

func (f *recordingFetcher) Fetch(_ context.Context, url string) (string, error) {
	f.urls = append(f.urls, url)
	return f.body, f.err
}

// recordingLogFetcher is a hermetic LogFetcher: it records the validated
// command it received.
type recordingLogFetcher struct {
	target  string
	command []string
	out     string
	err     error
}

func (f *recordingLogFetcher) Logs(_ context.Context, target string, command []string) (string, error) {
	f.target = target
	f.command = append([]string(nil), command...)
	return f.out, f.err
}

func TestValidateReadOnlyCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
		wantErr string
	}{
		{name: "cat", command: "cat /var/log/syslog", want: []string{"cat", "/var/log/syslog"}},
		{name: "tail range", command: "tail -n 200 /var/log/syslog", want: []string{"tail", "-n", "200", "/var/log/syslog"}},
		{name: "grep", command: "grep -i error /var/log/syslog", want: []string{"grep", "-i", "error", "/var/log/syslog"}},
		{name: "zgrep rotated", command: "zgrep panic /var/log/syslog.1.gz", want: []string{"zgrep", "panic", "/var/log/syslog.1.gz"}},
		{name: "empty", command: "  ", wantErr: "required"},
		{name: "write program refused", command: "rm -rf /", wantErr: "allowlist"},
		{name: "sed refused", command: "sed -n 1p /etc/passwd", wantErr: "allowlist"},
		{name: "awk refused", command: "awk '{print}' /var/log/syslog", wantErr: "allowlist"},
		{name: "journalctl refused", command: "journalctl -u sshd", wantErr: "allowlist"},
		{name: "chained command refused", command: "cat /var/log/syslog; rm -rf /", wantErr: "metacharacters"},
		{name: "pipe refused", command: "cat /var/log/syslog | grep error", wantErr: "metacharacters"},
		{name: "substitution refused", command: "cat $(whoami)", wantErr: "metacharacters"},
		{name: "redirect refused", command: "cat /x > /tmp/y", wantErr: "metacharacters"},
		{name: "backtick refused", command: "cat `whoami`", wantErr: "metacharacters"},
		{name: "follow refused", command: "tail -f /var/log/syslog", wantErr: "stream indefinitely"},
		{name: "follow long refused", command: "tail --follow=name /var/log/syslog", wantErr: "stream indefinitely"},
		{name: "multiline refused", command: "cat /x\nrm /y", wantErr: "single line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateReadOnlyCommand(tt.command)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("validateReadOnlyCommand(%q) = %v, want an error containing %q", tt.command, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateReadOnlyCommand(%q) error = %v, want it to contain %q", tt.command, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateReadOnlyCommand(%q) = %v", tt.command, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateReadOnlyCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestWebFetchToolTargets(t *testing.T) {
	tool := WebFetchTool(nil)
	tests := []struct {
		name string
		url  string
		want []string
	}{
		{name: "ip literal", url: "http://192.0.2.44/status", want: []string{"192.0.2.44"}},
		{name: "hostname with port", url: "https://app.acme.example:8443/x", want: []string{"app.acme.example"}},
		{name: "bracketed ipv6", url: "http://[2001:db8::1]:8080/x", want: []string{"2001:db8::1"}},
		{name: "not a url", url: "definitely not a url", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := tool.Targets(map[string]any{"url": tt.url})
			var got []string
			for _, target := range targets {
				got = append(got, target.Addr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Targets(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestWebFetchToolDelegatesToFetcher(t *testing.T) {
	fetcher := &recordingFetcher{body: "hello"}
	tool := WebFetchTool(fetcher)
	got, err := tool.Handler(context.Background(), map[string]any{"url": "http://192.0.2.44/x"})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if got != "hello" {
		t.Errorf("Handler() = %q, want the fetcher body", got)
	}
	if len(fetcher.urls) != 1 || fetcher.urls[0] != "http://192.0.2.44/x" {
		t.Errorf("fetcher saw %v, want the requested URL", fetcher.urls)
	}
}

func TestWebFetchToolWithoutFetcherRefuses(t *testing.T) {
	if _, err := WebFetchTool(nil).Handler(context.Background(), map[string]any{"url": "http://192.0.2.44/"}); err == nil {
		t.Error("web_fetch without a fetcher = nil error, want a refusal")
	}
}

func TestSSHLogsToolTargets(t *testing.T) {
	tool := SSHLogsTool(nil)
	tests := []struct {
		name   string
		target string
		want   []string
	}{
		{name: "plain host", target: "web01.acme.example", want: []string{"web01.acme.example"}},
		{name: "user and port", target: "eddy@web01.acme.example:2222", want: []string{"web01.acme.example"}},
		{name: "bracketed ipv6", target: "eddy@[2001:db8::1]:22", want: []string{"2001:db8::1"}},
		{name: "empty", target: "   ", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := tool.Targets(map[string]any{"target": tt.target})
			var got []string
			for _, target := range targets {
				got = append(got, target.Addr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Targets(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestSSHLogsToolEnforcesAllowlistBeforeTransport(t *testing.T) {
	fetcher := &recordingLogFetcher{out: "log line\n"}
	tool := SSHLogsTool(fetcher)

	got, err := tool.Handler(context.Background(), map[string]any{
		"target":  "web01.acme.example",
		"command": "tail -n 50 /var/log/syslog",
	})
	if err != nil {
		t.Fatalf("Handler() = %v", err)
	}
	if got != "log line\n" {
		t.Errorf("Handler() = %q, want the fetcher output", got)
	}
	if fetcher.target != "web01.acme.example" {
		t.Errorf("fetcher target = %q", fetcher.target)
	}
	if !reflect.DeepEqual(fetcher.command, []string{"tail", "-n", "50", "/var/log/syslog"}) {
		t.Errorf("fetcher command = %v, want the parsed argv", fetcher.command)
	}

	// A write-capable command never reaches the transport.
	if _, err := tool.Handler(context.Background(), map[string]any{
		"target":  "web01.acme.example",
		"command": "rm -rf /var/log",
	}); err == nil {
		t.Error("ssh_logs accepted a write-capable command")
	}
	if fetcher.target != "web01.acme.example" || len(fetcher.command) != 4 {
		t.Errorf("the refused command reached the transport: %q %v", fetcher.target, fetcher.command)
	}
}

func TestSSHLogsToolWithoutFetcherRefuses(t *testing.T) {
	_, err := SSHLogsTool(nil).Handler(context.Background(), map[string]any{
		"target":  "web01.acme.example",
		"command": "cat /var/log/syslog",
	})
	if err == nil {
		t.Error("ssh_logs without a fetcher = nil error, want a refusal")
	}
}

func TestFetcherErrorsSurface(t *testing.T) {
	want := errors.New("boom")
	if _, err := WebFetchTool(&recordingFetcher{err: want}).Handler(context.Background(),
		map[string]any{"url": "http://192.0.2.44/"}); !errors.Is(err, want) {
		t.Errorf("web_fetch error = %v, want the fetcher error", err)
	}
}
