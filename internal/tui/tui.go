// Package tui implements the terminal UI: the Bubble Tea program, streaming
// chat view, status bar, permission-prompt cards, and plan blocks.
//
// Boundary rule: tui renders events and collects decisions; it never talks to
// the model, executes tools, or contains policy logic — every permission
// decision still resolves through the policy engine.
//
// This build is the tracer bullet's thin stream (§9.1): the chat stream, the
// one-line status bar, and line input. Diffs, prompt cards, plan blocks, and
// the full slash-command set land in a later ticket.
package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/mobley-trent/styx-agent/internal/diff"
	"github.com/mobley-trent/styx-agent/internal/sessions"
)

const (
	// viewLines is the most lines of a single tool result rendered inline. The
	// stream stays readable even when a tool returns a large file.
	viewLines = 20
	// diffViewLines is the most lines of an inline diff rendered. A large diff
	// is summarized rather than flooding the stream.
	diffViewLines = 40
)

// Status is the persistent one-line status bar (§9.1): operating mode, model,
// and whatever else the app wants visible.
type Status struct {
	// Mode is "safe" or "engagement".
	Mode string
	// Model is the pinned model ID in force.
	Model string
	// Session is the current session ID, short-form.
	Session string
	// Isolation is the container enforcement level, empty until the container
	// layer lands (later ticket).
	Isolation string
	// Busy is true while the loop is working a turn.
	Busy bool
}

// Config wires the stream to the application. Every field is a callback the
// app owns; the UI holds no logic beyond rendering and input.
type Config struct {
	// Status returns the status line to render, read fresh each frame.
	Status func() Status
	// Submit receives a non-slash input line.
	Submit func(text string)
	// Command handles a slash command and returns text to render. A non-nil
	// error is rendered as an error line.
	Command func(name, arg string) (string, error)
	// Quit is called when the user asks to leave.
	Quit func()
}

// EventMsg carries one session event into the UI (§4.3).
type EventMsg struct {
	Event sessions.Event
}

// PromptKind discriminates a live operator interaction (§9.2, §9.3).
type PromptKind string

const (
	// PromptPermission is a policy permission prompt card (§9.3).
	PromptPermission PromptKind = "permission"
	// PromptDiff is a staged write's accept/reject diff review (§9.2).
	PromptDiff PromptKind = "diff"
	// PromptPlan is a proposed plan's approval card (§9.2).
	PromptPlan PromptKind = "plan"
)

// Prompt choices. They are the strings the app maps back onto the loop's
// decisions; the TUI itself decides nothing.
const (
	// ChoiceAllowOnce runs the call once.
	ChoiceAllowOnce = "allow-once"
	// ChoiceAllowSession runs this call and matching ones for the rest of the
	// session.
	ChoiceAllowSession = "allow-session"
	// ChoiceDeny refuses the call.
	ChoiceDeny = "deny"
	// ChoiceAccept applies a staged diff.
	ChoiceAccept = "accept"
	// ChoiceReject leaves the file untouched.
	ChoiceReject = "reject"
	// ChoiceAcceptRest applies this and every later diff this turn.
	ChoiceAcceptRest = "accept-rest"
	// ChoiceApprove pre-authorizes a plan for the turn.
	ChoiceApprove = "approve"
)

// Prompt is one live operator interaction, rendered as an inline card.
type Prompt struct {
	// Kind selects the card: a permission ask or a diff review.
	Kind PromptKind
	// Tool is the invoked tool's name.
	Tool string
	// Params is the call's verbatim parameter object.
	Params map[string]any
	// Reason is the engine's audit-facing reason for a prompt.
	Reason string
	// Risk is the call's risk class, empty when none applies.
	Risk string
	// Path is the file a diff review touches.
	Path string
	// Diff is the staged change under review.
	Diff *diff.FileDiff
	// Steps are a proposed plan's actions, for the approval card.
	Steps []sessions.PlanStep
}

// PromptMsg delivers a prompt to the UI from the loop's goroutine. Reply must
// be called exactly once, with one of the Choice constants, when the operator
// resolves the card.
type PromptMsg struct {
	Prompt Prompt
	Reply  func(choice string)
}

// RefreshMsg asks the UI to re-render without changing the stream. The app
// sends it when state the status bar reads changed outside an event — the
// busy flag, for instance.
type RefreshMsg struct{}

// Model is the thin chat-stream model.
type Model struct {
	cfg Config

	lines   []string
	partial string
	input   []rune

	prompt *Prompt
	reply  func(string)

	width  int
	height int
	quit   bool
}

// New builds the UI model.
func New(cfg Config) *Model {
	return &Model{cfg: cfg, width: 80, height: 24}
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyPressMsg:
		return m.key(msg)
	case EventMsg:
		m.apply(msg.Event)
	case PromptMsg:
		m.prompt = &msg.Prompt
		m.reply = msg.Reply
	}
	return m, nil
}

// key handles one key press.
func (m *Model) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.Key()
	// Quitting always works, even while a card is open: a live prompt must
	// never trap the operator.
	if key.Mod == tea.ModCtrl && (key.Code == 'c' || key.Code == 'd') {
		return m, m.quitCmd()
	}
	// A live card otherwise owns the keyboard: it is keyboard-first and
	// modal (§9.3).
	if m.prompt != nil {
		m.answerPrompt(key)
		return m, nil
	}
	switch {
	case key.Code == tea.KeyEnter || key.Code == tea.KeyReturn:
		m.submit()
	case key.Code == tea.KeyBackspace:
		if n := len(m.input); n > 0 {
			m.input = m.input[:n-1]
		}
	case key.Code == tea.KeyEscape:
		m.input = nil
	case key.Text != "":
		m.input = append(m.input, []rune(key.Text)...)
	}
	return m, nil
}

// submit handles the current input line.
func (m *Model) submit() {
	text := strings.TrimSpace(string(m.input))
	m.input = nil
	if text == "" {
		return
	}
	if !strings.HasPrefix(text, "/") {
		if m.cfg.Submit != nil {
			m.cfg.Submit(text)
		}
		return
	}

	name, arg, _ := strings.Cut(strings.TrimPrefix(text, "/"), " ")
	switch name {
	case "quit", "exit":
		m.quit = true
		if m.cfg.Quit != nil {
			m.cfg.Quit()
		}
		return
	}
	if m.cfg.Command == nil {
		m.append("no commands are available")
		return
	}
	out, err := m.cfg.Command(name, arg)
	if err != nil {
		m.append("! " + err.Error())
		return
	}
	if out != "" {
		m.append(out)
	}
}

// quitCmd is the command form of tea.Quit.
func (m *Model) quitCmd() tea.Cmd {
	m.quit = true
	if m.cfg.Quit != nil {
		m.cfg.Quit()
	}
	return func() tea.Msg { return tea.Quit() }
}

// answerPrompt resolves the live card from a key press and replies to the
// loop exactly once.
func (m *Model) answerPrompt(key tea.Key) {
	choice := promptChoice(m.prompt.Kind, key)
	if choice == "" {
		return
	}
	reply := m.reply
	m.prompt = nil
	m.reply = nil
	if reply != nil {
		reply(choice)
	}
}

// promptChoice maps a key press onto a choice for the card kind. An empty
// result means the key did not resolve the card.
func promptChoice(kind PromptKind, key tea.Key) string {
	yes := key.Code == 'y'
	no := key.Code == 'n'
	enter := key.Code == tea.KeyEnter || key.Code == tea.KeyReturn
	escape := key.Code == tea.KeyEscape

	if kind == PromptPlan {
		switch {
		case yes || enter || key.Code == 'a':
			return ChoiceApprove
		case no || escape:
			return ChoiceDeny
		default:
			return ""
		}
	}
	if kind == PromptDiff {
		switch {
		case key.Text == "A":
			return ChoiceAcceptRest
		case key.Code == 'a' || yes || enter:
			return ChoiceAccept
		case key.Code == 'r' || no || escape:
			return ChoiceReject
		default:
			return ""
		}
	}
	switch {
	case yes || enter:
		return ChoiceAllowOnce
	case key.Code == 'a' || key.Text == "s":
		return ChoiceAllowSession
	case no || escape:
		return ChoiceDeny
	default:
		return ""
	}
}

// promptBlock renders the live card, or nothing when no prompt is open.
func (m *Model) promptBlock() []string {
	if m.prompt == nil {
		return nil
	}
	p := m.prompt
	var lines []string

	if p.Kind == PromptPlan {
		lines = append(lines, cardStyle.Render(fmt.Sprintf("╭─ plan approval (%d step(s))", len(p.Steps))))
		for _, step := range p.Steps {
			lines = append(lines, "│ · "+step.Tool+" "+compactJSON(step.Params))
		}
		lines = append(lines, "│ "+
			cardKeyStyle.Render("y")+" approve   "+
			cardKeyStyle.Render("n")+" reject")
		lines = append(lines, cardStyle.Render("╰─"))
		return lines
	}

	if p.Kind == PromptDiff {
		header := "╭─ diff review"
		if p.Diff != nil {
			header += " · " + p.Diff.Summary()
		} else if p.Path != "" {
			header += " · " + p.Path
		}
		lines = append(lines, cardStyle.Render(header))
		if p.Diff != nil {
			for _, ln := range capDiffLines(p.Diff.Lines, diffViewLines) {
				lines = append(lines, "│ "+renderDiffLine(ln))
			}
		}
		lines = append(lines, "│ "+
			cardKeyStyle.Render("a")+" accept   "+
			cardKeyStyle.Render("r")+" reject   "+
			cardKeyStyle.Render("A")+" accept-all-rest-of-turn")
		lines = append(lines, cardStyle.Render("╰─"))
		return lines
	}

	header := "╭─ permission · " + p.Tool
	if risk := p.riskText(); risk != "" {
		header += " (" + risk + ")"
	}
	lines = append(lines, cardStyle.Render(header))
	lines = append(lines, "│ params: "+compactJSON(p.Params))
	lines = append(lines, "│ "+
		cardKeyStyle.Render("y")+" allow-once   "+
		cardKeyStyle.Render("a")+" allow-session   "+
		cardKeyStyle.Render("n")+" deny")
	lines = append(lines, cardStyle.Render("╰─"))
	return lines
}

// riskText names the card's risk class and prompt reason (§9.3).
func (p Prompt) riskText() string {
	var parts []string
	if p.Risk != "" {
		parts = append(parts, "risk: "+p.Risk)
	}
	if p.Reason != "" {
		parts = append(parts, "reason: "+p.Reason)
	}
	return strings.Join(parts, " · ")
}

// renderDiffLine renders one diff line with its marker and styling.
func renderDiffLine(ln diff.Line) string {
	switch ln.Op {
	case diff.OpAdd:
		return addStyle.Render("+" + ln.Text)
	case diff.OpRemove:
		return delStyle.Render("-" + ln.Text)
	default:
		return " " + ln.Text
	}
}

// capDiffLines keeps at most n diff lines and marks that more followed.
func capDiffLines(lines []diff.Line, n int) []diff.Line {
	if len(lines) <= n {
		return lines
	}
	out := append([]diff.Line(nil), lines[:n]...)
	out = append(out, diff.Line{Op: diff.OpContext, Text: fmt.Sprintf("… (%d more lines)", len(lines)-n)})
	return out
}

// View implements tea.Model.
func (m *Model) View() tea.View {
	var b strings.Builder

	// The transcript scrolls; the live card, input line, and status bar are
	// always visible, and the live partial answer takes a line when present.
	card := m.promptBlock()
	reserved := 2 + len(card)
	if m.partial != "" {
		reserved++
	}
	body := tailLines(m.body(), m.height-reserved)
	if len(body) > 0 {
		b.WriteString(strings.Join(body, "\n"))
		b.WriteByte('\n')
	}
	if m.partial != "" {
		b.WriteString(strings.TrimRight(m.partial, "\n"))
		b.WriteByte('\n')
	}
	for _, line := range card {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(m.inputLine())
	b.WriteByte('\n')
	b.WriteString(m.statusLine())

	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

// body is the rendered transcript: committed lines plus a live partial answer.
func (m *Model) body() []string {
	return m.lines
}

// inputLine is the prompt with the current buffer and a block cursor.
func (m *Model) inputLine() string {
	return promptStyle.Render("> ") + string(m.input) + "█"
}

// statusLine is the one-line status bar (§9.1).
func (m *Model) statusLine() string {
	status := Status{}
	if m.cfg.Status != nil {
		status = m.cfg.Status()
	}
	parts := []string{status.Mode}
	if status.Model != "" {
		parts = append(parts, status.Model)
	}
	if status.Isolation != "" {
		parts = append(parts, status.Isolation)
	}
	if status.Session != "" {
		parts = append(parts, status.Session)
	}
	if status.Busy {
		parts = append(parts, "working…")
	}
	text := strings.Join(parts, " · ")
	if pad := m.width - lipgloss.Width(text); pad > 0 {
		text += strings.Repeat(" ", pad)
	}
	return statusStyle.Render(text)
}

// apply renders one session event onto the stream.
func (m *Model) apply(ev sessions.Event) {
	switch ev.Kind {
	case sessions.KindUser:
		m.commitPartial()
		m.append("> " + ev.Text)
	case sessions.KindTextDelta:
		m.partial += ev.Text
	case sessions.KindAssistant:
		// The assembled message supersedes any deltas already rendered.
		m.partial = ""
		if strings.TrimSpace(ev.Text) != "" {
			m.append(ev.Text)
		}
	case sessions.KindToolCall:
		m.commitPartial()
		m.append(toolStyle.Render(fmt.Sprintf("  · %s %s → %s", ev.Tool, compactJSON(ev.Params), verdictText(ev))))
	case sessions.KindToolResult:
		m.commitPartial()
		switch {
		case ev.Failure != "":
			m.append(failStyle.Render("    ✗ " + ev.Failure))
		case ev.Result == "":
			m.append("    (no output)")
		default:
			m.append(indentLines(capLines(ev.Result, viewLines), "    "))
		}
	case sessions.KindDiff:
		m.commitPartial()
		if ev.Diff != nil {
			m.append("  " + diffHeaderStyle.Render(ev.Diff.Summary()))
			lines := make([]string, 0, len(ev.Diff.Lines))
			for _, ln := range capDiffLines(ev.Diff.Lines, diffViewLines) {
				lines = append(lines, "    "+renderDiffLine(ln))
			}
			m.append(strings.Join(lines, "\n"))
		} else if ev.Path != "" {
			m.append("  diff: " + ev.Path)
		}
	case sessions.KindPlan:
		m.commitPartial()
		m.append("  " + diffHeaderStyle.Render("plan"))
		for _, step := range ev.Steps {
			m.append("    · " + step.Tool + " " + compactJSON(step.Params))
		}
	case sessions.KindCompaction:
		m.append("… compacted: " + ev.Detail)
	case sessions.KindEngagement:
		m.commitPartial()
		switch {
		case ev.Engagement != "":
			m.append("⚑ engagement active: " + ev.Engagement)
		case ev.Detail != "":
			m.append("⚑ " + ev.Detail)
		}
	case sessions.KindIsolation:
		m.commitPartial()
		text := ev.Detail
		if text == "" {
			text = ev.Isolation
		}
		m.append(bannerStyle.Render("⚑ " + text))
	case sessions.KindError:
		m.commitPartial()
		m.append(failStyle.Render("! " + ev.Failure))
	}
}

// verdictText renders a tool call's verdict and reason.
func verdictText(ev sessions.Event) string {
	if ev.Reason == "" {
		return ev.Verdict
	}
	return ev.Verdict + " (" + ev.Reason + ")"
}

// append adds a line (or several) to the transcript.
func (m *Model) append(text string) {
	if strings.TrimRight(text, "\n") == "" {
		return
	}
	m.lines = append(m.lines, strings.Split(strings.TrimRight(text, "\n"), "\n")...)
}

// commitPartial folds a live partial answer into the transcript.
func (m *Model) commitPartial() {
	if m.partial == "" {
		return
	}
	m.append(m.partial)
	m.partial = ""
}

// tailLines keeps the last n lines: the stream scrolls, newest at the bottom.
// A non-positive budget drops the transcript entirely rather than flooding a
// too-small terminal.
func tailLines(lines []string, n int) []string {
	if n <= 0 {
		return nil
	}
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

// capLines keeps at most n lines and marks that more followed.
func capLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n… (%d more lines)", len(lines)-n)
}

// indentLines indents every line of a block.
func indentLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// compactJSON renders a parameter object on one line.
func compactJSON(v any) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 120 {
		s = truncate(s, 120) + "…"
	}
	return s
}

// truncate cuts a string to n bytes without splitting a rune.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Styles. One polished dark theme and a light variant land with the full TUI;
// this build keeps the chrome minimal and legible on both.
var (
	statusStyle     = lipgloss.NewStyle().Bold(true)
	promptStyle     = lipgloss.NewStyle().Bold(true)
	toolStyle       = lipgloss.NewStyle().Faint(true)
	failStyle       = lipgloss.NewStyle().Bold(true)
	cardStyle       = lipgloss.NewStyle().Faint(true)
	cardKeyStyle    = lipgloss.NewStyle().Bold(true)
	bannerStyle     = lipgloss.NewStyle().Bold(true)
	diffHeaderStyle = lipgloss.NewStyle().Bold(true)
	addStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	delStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)
