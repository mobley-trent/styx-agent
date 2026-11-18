package browser

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mobley-trent/styx-agent/internal/engagementstate"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

func TestProfileDirDerivesLikeTheStores(t *testing.T) {
	root := t.TempDir()
	got := ProfileDir(root, "/work/acme", "External: Q4")
	want := filepath.Join(root, sessions.ProjectKey("/work/acme"), engagementstate.EngagementKey("External: Q4"))
	if got != want {
		t.Errorf("ProfileDir() = %q, want %q", got, want)
	}
}

func TestProfileLockRefusesASecondWriter(t *testing.T) {
	first, err := OpenProfile(ProfileOptions{Root: t.TempDir(), ProjectDir: "/work/acme", Engagement: "q4", Session: "alpha"})
	if err != nil {
		t.Fatalf("OpenProfile() = %v", err)
	}
	if err := first.Lock(); err != nil {
		t.Fatalf("Lock() = %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := OpenProfile(ProfileOptions{Root: firstRoot(t, first), ProjectDir: "/work/acme", Engagement: "q4", Session: "beta"})
	if err != nil {
		t.Fatalf("OpenProfile(second) = %v", err)
	}
	err = second.Lock()
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Lock() = %v, want ErrLocked", err)
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("error = %v, want it to name the locking session", err)
	}
}

func TestProfileReclaimsAStaleLock(t *testing.T) {
	root := t.TempDir()
	profile, err := OpenProfile(ProfileOptions{Root: root, ProjectDir: "/work/acme", Engagement: "q4", Session: "alpha"})
	if err != nil {
		t.Fatalf("OpenProfile() = %v", err)
	}
	// A lock left by a process that no longer exists is reclaimed rather than
	// blocking every future session.
	stale, err := json.Marshal(lockRecord{PID: 1 << 30, Session: "gone", At: time.Now()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(profile.Dir(), ".lock"), stale, 0o600); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}
	if err := profile.Lock(); err != nil {
		t.Fatalf("Lock() over a stale holder = %v", err)
	}
	if err := profile.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := os.Stat(filepath.Join(profile.Dir(), ".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lock survives Close: %v", err)
	}
}

func TestProfileRelaunchKeepsCookies(t *testing.T) {
	root := t.TempDir()
	profile, err := OpenProfile(ProfileOptions{Root: root, ProjectDir: "/work/acme", Engagement: "q4", Session: "alpha"})
	if err != nil {
		t.Fatalf("OpenProfile() = %v", err)
	}
	if err := profile.Lock(); err != nil {
		t.Fatalf("Lock() = %v", err)
	}
	cookies := filepath.Join(profile.Dir(), "Cookies")
	if err := os.WriteFile(cookies, []byte("session=abc"), 0o600); err != nil {
		t.Fatalf("write cookies: %v", err)
	}
	// A crash releases the lock but keeps the profile.
	if err := profile.Unlock(); err != nil {
		t.Fatalf("Unlock() = %v", err)
	}
	if err := profile.Lock(); err != nil {
		t.Fatalf("re-Lock() = %v", err)
	}
	if _, err := os.Stat(cookies); err != nil {
		t.Errorf("the profile's cookies did not survive the relaunch: %v", err)
	}
	if err := profile.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := os.Stat(cookies); err != nil {
		t.Errorf("an engagement profile must outlive the session, got %v", err)
	}
}

func TestSafeModeProfileIsEphemeral(t *testing.T) {
	profile, err := OpenProfile(ProfileOptions{Root: t.TempDir(), ProjectDir: "/work/acme", Session: "alpha"})
	if err != nil {
		t.Fatalf("OpenProfile() = %v", err)
	}
	if !profile.Ephemeral() {
		t.Fatal("safe mode's profile is not ephemeral")
	}
	if err := profile.Lock(); err != nil {
		t.Fatalf("Lock() = %v", err)
	}
	dir := profile.Dir()
	if err := profile.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the ephemeral profile survives Close: %v", err)
	}
}

// firstRoot returns the root a profile lives under, so a second test profile
// names the same directory.
func firstRoot(t *testing.T, profile *Profile) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(profile.Dir()))
}
