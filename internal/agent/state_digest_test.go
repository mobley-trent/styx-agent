package agent

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/audit"
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/policy"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// scriptedDigest is a StateDigest that hands out a scripted sequence and
// records the forces it was asked for.
type scriptedDigest struct {
	mu     sync.Mutex
	bodies []string
	forces []bool
	i      int
}

func (d *scriptedDigest) Digest(force bool) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forces = append(d.forces, force)
	if d.i >= len(d.bodies) {
		return "", false
	}
	body := d.bodies[d.i]
	d.i++
	return body, true
}

// digestMessages returns the digest system messages in a conversation.
func digestMessages(messages []model.Message) []string {
	var out []string
	for _, m := range messages {
		if m.Role == model.RoleSystem && strings.HasPrefix(m.Content, digestPrefix) {
			out = append(out, m.Content)
		}
	}
	return out
}

func TestLoopAppendsTheStateDigestWhenItIsDue(t *testing.T) {
	digest := &scriptedDigest{bodies: []string{"hosts 1\nstate_query for detail"}}
	events := &collector{}
	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(fakemodel.Text("done"))),
		mustRegistry(t, testTool("noop", func(context.Context, map[string]any) (string, error) { return "ok", nil })),
		mustEngine(t, policy.ModeEngagement),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
		WithEmitter(events.emit),
		WithStateDigest(digest),
	)

	result, err := loop.Run(context.Background(), nil, "recon")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	digests := digestMessages(result.Messages)
	if len(digests) != 1 {
		t.Fatalf("digest messages = %d, want 1", len(digests))
	}
	if !strings.HasPrefix(digests[0], digestPrefix) || !strings.Contains(digests[0], "hosts 1") {
		t.Errorf("digest message = %q, want the prefix and the body", digests[0])
	}
	// The digest is appended at the turn boundary: after the human turn it
	// describes, before the model's answer.
	if result.Messages[0].Role != model.RoleUser {
		t.Fatalf("first message = %q, want the human turn", result.Messages[0].Role)
	}
	if !strings.HasPrefix(result.Messages[1].Content, digestPrefix) {
		t.Errorf("digest should follow the human turn, got %q", result.Messages[1].Content)
	}

	// The digest is persisted, so "nothing renders that isn't also persisted"
	// holds for it like anything else.
	emitted := events.byKind(sessions.KindStateDigest)
	if len(emitted) != 1 || !strings.Contains(emitted[0].Text, "hosts 1") {
		t.Fatalf("state digest events = %+v, want one carrying the body", emitted)
	}
	if !sessions.KindStateDigest.Preserved() {
		t.Errorf("a digest must be persisted: it is a view of the record, not a stream delta")
	}
}

func TestLoopReappendsTheDigestAfterEviction(t *testing.T) {
	digest := &scriptedDigest{bodies: []string{"hosts 1", "hosts 2", "hosts 3"}}
	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(
			fakemodel.Text("first"),
			fakemodel.Text("second"),
			fakemodel.Text("third"),
		)),
		mustRegistry(t, testTool("noop", func(context.Context, map[string]any) (string, error) { return "ok", nil })),
		mustEngine(t, policy.ModeEngagement),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
		WithStateDigest(digest),
	)

	first, err := loop.Run(context.Background(), nil, "one")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	// The next turn's history carries the digest, so the loop does not force.
	second, err := loop.Run(context.Background(), first.Messages, "two")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := digestMessages(second.Messages); len(got) != 2 {
		t.Fatalf("digest messages = %d, want the first carried plus the second", len(got))
	}

	// A conversation whose digest is gone — compaction evicted it, or /clear
	// dropped it — gets one back, which is what the force flag is for.
	evicted := make([]model.Message, 0, len(second.Messages))
	for _, m := range second.Messages {
		if m.Role == model.RoleSystem && strings.HasPrefix(m.Content, digestPrefix) {
			continue
		}
		evicted = append(evicted, m)
	}
	third, err := loop.Run(context.Background(), evicted, "three")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := digestMessages(third.Messages); len(got) != 1 {
		t.Fatalf("digest messages after eviction = %d, want exactly one restored digest", len(got))
	}
	digest.mu.Lock()
	forces := append([]bool(nil), digest.forces...)
	digest.mu.Unlock()
	// The first turn forces (a fresh conversation carries no digest), the
	// second does not (the first digest is still there), and the third forces
	// again because the conversation it resumes carries none.
	if len(forces) != 3 || !forces[0] || forces[1] || !forces[2] {
		t.Errorf("forces = %v, want [true false true]", forces)
	}
}

func TestLoopAppendsNoDigestWithoutADigestSource(t *testing.T) {
	loop := NewLoop(
		fakemodel.New(fakemodel.WithTurns(fakemodel.Text("done"))),
		mustRegistry(t, testTool("noop", func(context.Context, map[string]any) (string, error) { return "ok", nil })),
		mustEngine(t, policy.ModeSafe),
		audit.NewWriter(&bytes.Buffer{}),
		testSystemPrompt,
	)
	result, err := loop.Run(context.Background(), nil, "hello")
	if err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if got := digestMessages(result.Messages); len(got) != 0 {
		t.Errorf("digest messages = %v, want none: a loop without a digest source appends nothing", got)
	}
}

func TestConversationReplaysTheDigest(t *testing.T) {
	events := []sessions.Event{
		{Kind: sessions.KindUser, Text: "recon the host"},
		{Kind: sessions.KindAssistant, Text: "starting"},
		{Kind: sessions.KindStateDigest, Text: "hosts 1\nstate_query for detail"},
		{Kind: sessions.KindUser, Text: "next"},
	}
	messages := Conversation(events)
	var digests []string
	for _, m := range messages {
		if strings.HasPrefix(m.Content, digestPrefix) {
			digests = append(digests, m.Content)
		}
	}
	if len(digests) != 1 || !strings.Contains(digests[0], "hosts 1") {
		t.Fatalf("Conversation() digest messages = %v, want one replay", digests)
	}
	if messages[2].Role != model.RoleSystem {
		t.Errorf("a replayed digest should be a system message, got %q", messages[2].Role)
	}
}
