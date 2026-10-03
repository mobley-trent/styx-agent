package agent

import (
	"github.com/mobley-trent/styx-agent/internal/model"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

// callRefs converts a turn's tool calls into their persisted form.
func callRefs(calls []model.ToolCall) []sessions.ToolCallRef {
	if len(calls) == 0 {
		return nil
	}
	out := make([]sessions.ToolCallRef, 0, len(calls))
	for _, c := range calls {
		out = append(out, sessions.ToolCallRef{ID: c.ID, Name: c.Name, Arguments: c.Arguments})
	}
	return out
}

// Conversation rebuilds the model conversation a session's events describe,
// for /resume (§10.1). It reads only the events that carry conversation
// structure: human turns, assistant turns, and tool results. The system prompt
// is never persisted and never rebuilt here — the caller assembles it fresh,
// because it is the byte-stable prefix, not part of the transcript (§3.3).
//
// A session interrupted mid-turn (a trailing tool call with no result) still
// yields a valid conversation: the dangling assistant turn and anything after
// it are dropped, because replaying a call the model never got an answer to is
// not a state the provider accepts.
func Conversation(events []sessions.Event) []model.Message {
	var messages []model.Message
	for _, ev := range events {
		// A subagent runs in an isolated context (§4.2): its messages are not
		// part of the main conversation, only the dispatch call and its report
		// are. Skip everything attributed to a run or the resumed session would
		// replay a worker's transcript as the main agent's own.
		if ev.Subagent != "" {
			continue
		}
		switch ev.Kind {
		case sessions.KindUser:
			messages = append(messages, model.Message{Role: model.RoleUser, Content: ev.Text})
		case sessions.KindAssistant:
			calls := make([]model.ToolCall, 0, len(ev.Calls))
			for _, c := range ev.Calls {
				calls = append(calls, model.ToolCall{ID: c.ID, Name: c.Name, Arguments: c.Arguments})
			}
			messages = append(messages, model.Message{
				Role:      model.RoleAssistant,
				Content:   ev.Text,
				Reasoning: ev.Reasoning,
				ToolCalls: calls,
			})
		case sessions.KindToolResult:
			content := ev.Result
			if ev.Failure != "" {
				content = ev.Failure
			}
			messages = append(messages, model.Message{
				Role:       model.RoleTool,
				ToolCallID: ev.CallID,
				Content:    content,
			})
		}
	}
	return dropDanglingCalls(messages)
}

// dropDanglingCalls truncates the conversation at the first assistant turn
// with an unanswered tool call.
func dropDanglingCalls(messages []model.Message) []model.Message {
	for i, m := range messages {
		if m.Role != model.RoleAssistant || len(m.ToolCalls) == 0 {
			continue
		}
		for _, call := range m.ToolCalls {
			if !answeredAfter(messages[i+1:], call.ID) {
				return messages[:i]
			}
		}
	}
	return messages
}

// answeredAfter reports whether a tool message answering id follows.
func answeredAfter(messages []model.Message, id string) bool {
	for _, m := range messages {
		if m.Role == model.RoleTool && m.ToolCallID == id {
			return true
		}
	}
	return false
}
