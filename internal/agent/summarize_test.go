package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

func TestModelSummarizerStreamsAndForwardsInstruction(t *testing.T) {
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("condensed ", "history")))
	s := NewModelSummarizer(fake, model.DefaultModelID)

	got, err := s.Summarize(context.Background(), "preserve every IP address", []model.Message{
		userMsg("scan the host"),
		toolMsg("c1", "open ports 22, 443"),
	})
	if err != nil {
		t.Fatalf("Summarize() = %v", err)
	}
	if got != "condensed history" {
		t.Errorf("summary = %q, want the streamed text", got)
	}

	req, ok := fake.LastRequest()
	if !ok {
		t.Fatal("the summarizer made no model request")
	}
	if req.Model != model.DefaultModelID {
		t.Errorf("summarizer model = %q, want the pinned ID", req.Model)
	}
	if len(req.Messages) != 2 || !strings.Contains(req.Messages[0].Content, "context compactor") {
		t.Errorf("summarizer request lacks its system prompt: %+v", req.Messages)
	}
	ask := req.Messages[1].Content
	for _, want := range []string{"USER:", "TOOL RESULT:", "scan the host", "open ports 22, 443", "preserve every IP address"} {
		if !strings.Contains(ask, want) {
			t.Errorf("summarizer ask is missing %q:\n%s", want, ask)
		}
	}
}

func TestModelSummarizerRejectsEmptyOutput(t *testing.T) {
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Text("   ")))
	s := NewModelSummarizer(fake, model.DefaultModelID)
	if _, err := s.Summarize(context.Background(), "", []model.Message{userMsg("x")}); err == nil {
		t.Fatal("Summarize() = nil, want an error for an empty summary")
	}
}

func TestModelSummarizerPropagatesStreamError(t *testing.T) {
	sentinel := errors.New("stream broke")
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.StreamError(sentinel)))
	s := NewModelSummarizer(fake, model.DefaultModelID)
	if _, err := s.Summarize(context.Background(), "", []model.Message{userMsg("x")}); !errors.Is(err, sentinel) {
		t.Fatalf("Summarize() = %v, want the stream error", err)
	}
}

func TestModelSummarizerRequiresClient(t *testing.T) {
	s := NewModelSummarizer(nil, model.DefaultModelID)
	if _, err := s.Summarize(context.Background(), "", []model.Message{userMsg("x")}); err == nil {
		t.Fatal("Summarize() = nil, want an error with no client")
	}
}

func TestModelSummarizerEmitsUsage(t *testing.T) {
	fake := fakemodel.New(fakemodel.WithTurns(fakemodel.Turn{
		Text: []string{"condensed"},
		Usage: &model.Usage{
			PromptTokens: 300, CompletionTokens: 30,
			CacheHitTokens: 200, CacheMissTokens: 100,
		},
	}))
	events := &collector{}
	s := NewModelSummarizer(fake, model.DefaultModelID, WithSummarizerUsageEmitter(events.emit))

	if _, err := s.Summarize(context.Background(), "", []model.Message{userMsg("x")}); err != nil {
		t.Fatalf("Summarize() = %v", err)
	}
	usage := events.byKind(sessions.KindUsage)
	if len(usage) != 1 {
		t.Fatalf("usage events = %d, want the summarizer's turn counted", len(usage))
	}
	if usage[0].Model != model.DefaultModelID || usage[0].CacheHitTokens != 200 || usage[0].CacheMissTokens != 100 {
		t.Errorf("usage event = %+v, want the model and cache split", usage[0])
	}
}
