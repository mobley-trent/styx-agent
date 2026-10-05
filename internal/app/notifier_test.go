package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// countingUpdateFetcher records how many times the notifier fetched. The
// notifier is allowed at most one fetch per process.
type countingUpdateFetcher struct {
	calls int
	body  string
	err   error
}

func (f *countingUpdateFetcher) Fetch(context.Context, string) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.body), nil
}

func TestUpdateNotifierEmitsWhenNewer(t *testing.T) {
	dir := t.TempDir()
	opts := buildOptions(t, dir, fakemodel.New())
	opts.Version = "v0.1.0"
	fetcher := &countingUpdateFetcher{body: `{"tag_name":"v0.2.0","html_url":"https://example/rel"}`}
	opts.UpdateFetcher = fetcher

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	var got []sessions.Event
	h.setUI(func(ev sessions.Event) { got = append(got, ev) })

	h.CheckForUpdate(context.Background())
	// A second check must not fetch again (§12.3: a single fetch).
	h.CheckForUpdate(context.Background())

	if fetcher.calls != 1 {
		t.Errorf("notifier fetched %d times, want 1", fetcher.calls)
	}
	var updates []sessions.Event
	for _, ev := range got {
		if ev.Kind == sessions.KindUpdate {
			updates = append(updates, ev)
		}
	}
	if len(updates) != 1 {
		t.Fatalf("emitted %d update events, want 1: %+v", len(updates), got)
	}
	if detail := updates[0].Detail; !strings.Contains(detail, "v0.2.0") || !strings.Contains(detail, "v0.1.0") || !strings.Contains(detail, "https://example/rel") {
		t.Errorf("update detail = %q, want latest, current, and url", detail)
	}
}

func TestUpdateNotifierDisabled(t *testing.T) {
	tests := []struct {
		name          string
		env           map[string]string
		version       string
		sourceBuild   bool
		engagement    bool
		configEnabled bool
	}{
		{name: "env opt-out", env: map[string]string{"STYX_NO_UPDATE_NOTIFIER": "1"}},
		{name: "source build", sourceBuild: true, version: "v0.1.0"},
		{name: "engagement active", engagement: true, version: "v0.1.0"},
		{name: "config opt-out", configEnabled: false, version: "v0.1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			opts := buildOptions(t, dir, fakemodel.New())
			opts.Version = tt.version
			opts.SourceBuild = tt.sourceBuild
			if tt.engagement {
				opts.Engagement = engagementFixture
			}
			if !tt.configEnabled {
				configHome := t.TempDir()
				t.Setenv("XDG_CONFIG_HOME", configHome)
				writeFile(t, configHome, "styx/config.yaml", "update_notifier: false\n")
			}
			fetcher := &countingUpdateFetcher{body: `{"tag_name":"v0.2.0"}`}
			opts.UpdateFetcher = fetcher

			h, err := Build(context.Background(), opts)
			if err != nil {
				t.Fatalf("Build() = %v, want nil", err)
			}
			defer func() { _ = h.Close() }()

			h.CheckForUpdate(context.Background())
			if fetcher.calls != 0 {
				t.Errorf("disabled notifier fetched %d times, want 0", fetcher.calls)
			}
		})
	}
}

func TestUpdateNotifierFetchErrorIsSilent(t *testing.T) {
	dir := t.TempDir()
	opts := buildOptions(t, dir, fakemodel.New())
	opts.Version = "v0.1.0"
	opts.UpdateFetcher = &countingUpdateFetcher{err: errors.New("offline")}

	h, err := Build(context.Background(), opts)
	if err != nil {
		t.Fatalf("Build() = %v, want nil", err)
	}
	defer func() { _ = h.Close() }()

	var got []sessions.Event
	h.setUI(func(ev sessions.Event) { got = append(got, ev) })
	h.CheckForUpdate(context.Background())
	for _, ev := range got {
		if ev.Kind == sessions.KindUpdate {
			t.Errorf("a failed fetch emitted an update event: %+v", ev)
		}
	}
}
