package policy

import (
	"testing"
	"time"
)

// fixedClock parses an RFC3339 instant and returns a clock pinned to it.
func fixedClock(t *testing.T, rfc3339 string) func() time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		t.Fatalf("fixedClock(%s): %v", rfc3339, err)
	}
	return func() time.Time { return ts }
}

func TestROEExploitGate(t *testing.T) {
	tests := []struct {
		name    string
		roe     *ROE
		call    Call
		wantErr bool
	}{
		{
			name:    "exploit-class denied when exploit_allowed false",
			roe:     &ROE{ExploitAllowed: false},
			call:    Call{Tool: "exploit_payload", ExploitClass: true},
			wantErr: true,
		},
		{
			name:    "exploit-class allowed when exploit_allowed true",
			roe:     &ROE{ExploitAllowed: true},
			call:    Call{Tool: "exploit_payload", ExploitClass: true},
			wantErr: false,
		},
		{
			name:    "recon unaffected by exploit gate",
			roe:     &ROE{ExploitAllowed: false},
			call:    Call{Tool: "web_fetch", ScopeTargets: []Target{{Addr: "10.0.0.5"}}},
			wantErr: false,
		},
		{
			name:    "non-exploit tool ignores exploit_allowed",
			roe:     &ROE{ExploitAllowed: false},
			call:    Call{Tool: "bash", Params: map[string]any{"command": "ls"}},
			wantErr: false,
		},
		{
			name:    "nil ROE limits nothing",
			roe:     nil,
			call:    Call{Tool: "exploit_payload", ExploitClass: true},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.roe.Check(tt.call, time.Now())
			if (err != nil) != tt.wantErr {
				t.Errorf("ROE.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestROEDestructiveGate(t *testing.T) {
	tests := []struct {
		name    string
		roe     *ROE
		call    Call
		wantErr bool
	}{
		{
			name:    "destructive denied when destructive_forbidden",
			roe:     &ROE{DestructiveForbidden: true},
			call:    Call{Tool: "bash", Params: map[string]any{"command": "rm -rf /"}, Destructive: true},
			wantErr: true,
		},
		{
			name:    "destructive permitted when not forbidden",
			roe:     &ROE{DestructiveForbidden: false},
			call:    Call{Tool: "bash", Params: map[string]any{"command": "rm -rf /tmp/x"}, Destructive: true},
			wantErr: false,
		},
		{
			name:    "non-destructive call unaffected",
			roe:     &ROE{DestructiveForbidden: true},
			call:    Call{Tool: "bash", Params: map[string]any{"command": "nmap -sV 10.0.0.1"}},
			wantErr: false,
		},
		{
			name:    "destructive beats exploit allowance (independent gates)",
			roe:     &ROE{ExploitAllowed: true, DestructiveForbidden: true},
			call:    Call{Tool: "exploit_payload", ExploitClass: true, Destructive: true},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.roe.Check(tt.call, time.Now())
			if (err != nil) != tt.wantErr {
				t.Errorf("ROE.Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestROETimeWindow(t *testing.T) {
	// Window 08:00–18:00 America/New_York (EDT = UTC-4 in September).
	window := &ROE{
		TimeWindow: &TimeWindow{Start: "08:00", End: "18:00", TZ: "America/New_York"},
	}
	netCall := Call{Tool: "web_fetch", ScopeTargets: []Target{{Addr: "10.0.0.1"}}}
	fileCall := Call{Tool: "read_file"}

	tests := []struct {
		name    string
		now     string
		call    Call
		roe     *ROE
		wantErr bool
	}{
		{
			name: "inside window allows",
			now:  "2026-09-29T12:00:00-04:00", // noon EDT
			call: netCall, roe: window, wantErr: false,
		},
		{
			name: "before window denies",
			now:  "2026-09-29T07:59:00-04:00",
			call: netCall, roe: window, wantErr: true,
		},
		{
			name: "boundary start included",
			now:  "2026-09-29T08:00:00-04:00",
			call: netCall, roe: window, wantErr: false,
		},
		{
			name: "boundary end excluded",
			now:  "2026-09-29T18:00:00-04:00",
			call: netCall, roe: window, wantErr: true,
		},
		{
			name: "same instant expressed in UTC honors tz",
			now:  "2026-09-29T16:00:00Z", // noon EDT
			call: netCall, roe: window, wantErr: false,
		},
		{
			name: "utc clock outside EDT window denies",
			now:  "2026-09-29T03:00:00Z", // 23:00 previous day EDT
			call: netCall, roe: window, wantErr: true,
		},
		{
			name: "file read ignores window entirely",
			now:  "2026-09-29T03:00:00Z",
			call: fileCall, roe: window, wantErr: false,
		},
		{
			name: "exec binds the window too",
			now:  "2026-09-29T03:00:00Z",
			call: execCall("nmap -sV 10.0.0.1"), roe: window, wantErr: true,
		},
		{
			name: "exec inside window allows",
			now:  "2026-09-29T12:00:00-04:00",
			call: execCall("nmap -sV 10.0.0.1"), roe: window, wantErr: false,
		},
		{
			name:    "default tz is UTC when omitted",
			now:     "2026-09-29T07:59:00Z",
			call:    netCall,
			roe:     &ROE{TimeWindow: &TimeWindow{Start: "08:00", End: "18:00"}},
			wantErr: true,
		},
		{
			name:    "default tz UTC inside window allows",
			now:     "2026-09-29T08:00:00Z",
			call:    netCall,
			roe:     &ROE{TimeWindow: &TimeWindow{Start: "08:00", End: "18:00"}},
			wantErr: false,
		},
		{
			name:    "window crossing midnight holds overnight",
			now:     "2026-09-29T01:00:00Z",
			call:    netCall,
			roe:     &ROE{TimeWindow: &TimeWindow{Start: "22:00", End: "06:00"}},
			wantErr: false,
		},
		{
			name:    "midnight-crossing window denies by day",
			now:     "2026-09-29T12:00:00Z",
			call:    netCall,
			roe:     &ROE{TimeWindow: &TimeWindow{Start: "22:00", End: "06:00"}},
			wantErr: true,
		},
		{
			name:    "nil window binds nothing",
			now:     "2026-09-29T03:00:00Z",
			call:    netCall,
			roe:     &ROE{},
			wantErr: false,
		},
		{
			name:    "invalid start time is a hard error",
			now:     "2026-09-29T12:00:00Z",
			call:    netCall,
			roe:     &ROE{TimeWindow: &TimeWindow{Start: "25:00", End: "18:00"}},
			wantErr: true,
		},
		{
			name:    "unknown tz is a hard error",
			now:     "2026-09-29T12:00:00Z",
			call:    netCall,
			roe:     &ROE{TimeWindow: &TimeWindow{Start: "08:00", End: "18:00", TZ: "Mars/Olympus"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.roe.Check(tt.call, fixedClock(t, tt.now)())
			if (err != nil) != tt.wantErr {
				t.Errorf("ROE.Check(now=%s) error = %v, wantErr %v", tt.now, err, tt.wantErr)
			}
		})
	}
}

func TestNetworkOrExec(t *testing.T) {
	tests := []struct {
		name string
		call Call
		want bool
	}{
		{name: "no targets, not exploit", call: Call{Tool: "read_file"}, want: false},
		{name: "targets present", call: Call{Tool: "web_fetch", ScopeTargets: []Target{{Addr: "10.0.0.1"}}}, want: true},
		{name: "exploit-class counts even without targets", call: Call{Tool: "exploit_payload", ExploitClass: true}, want: true},
		{name: "destructive alone is not network/exec", call: Call{Tool: "bash", Destructive: true}, want: true}, // bash is exec
		{name: "bash is exec", call: execCall("ls"), want: true},
		{name: "code_exec is exec", call: Call{Tool: "code_exec", Params: map[string]any{"lang": "python"}}, want: true},
		{name: "write is not exec", call: Call{Tool: "write_file"}, want: false},
		{name: "skill is not exec", call: Call{Tool: "skill"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.call.NetworkOrExec(); got != tt.want {
				t.Errorf("NetworkOrExec(%s) = %v, want %v", tt.call.Tool, got, tt.want)
			}
		})
	}
}

func TestModeValid(t *testing.T) {
	for _, m := range []Mode{ModeSafe, ModeEngagement} {
		if !m.Valid() {
			t.Errorf("Mode(%s).Valid() = false, want true", m)
		}
	}
	if Mode("bogus").Valid() {
		t.Errorf("Mode(bogus).Valid() = true, want false")
	}
}
