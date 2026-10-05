package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/model/fakemodel"
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
