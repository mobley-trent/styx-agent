// Package tui implements the terminal UI: the Bubble Tea program, streaming
// chat view, status bar, permission-prompt cards, and plan blocks.
//
// Boundary rule: tui renders events and collects decisions; it never talks to
// the model, executes tools, or contains policy logic — every permission
// decision still resolves through the policy engine.
//
// This build is the complete stream (§9): the chat stream, the one-line status
// bar, line input, diffs, prompt cards, plan blocks, subagent blocks, and the
// dark/light themes auto-selected from the terminal background.
package tui

import (
	"fmt"
	"strings"
	"time"
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
	// defaultWidth and defaultHeight are the terminal dimensions assumed until
	// the first WindowSizeMsg arrives.
	defaultWidth  = 80
	defaultHeight = 24
	// dispatchToolName is the delegation tool. Its result is the subagent
	// block's report, so the main stream skips the duplicate result line
	// (§4.2).
	dispatchToolName = "dispatch_subagent"
)

// spinnerInterval is how fast a running subagent's spinner advances.
const spinnerInterval = 120 * time.Millisecond

// spinnerFrames is the running subagent block's animation.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerMsg advances the running subagent blocks' spinners.
type spinnerMsg struct{}

// spinnerTick schedules the next spinner frame.
func spinnerTick() tea.Cmd {
	return tea.Tick(spinnerInterval, func(time.Time) tea.Msg { return spinnerMsg{} })
}

// Status is the persistent one-line status bar (§9.1): operating mode, model,
// and whatever else the app wants visible.
type Status struct {
	// Mode is "safe" or "engagement".
	Mode string
	// Packs is the active-pack readout — the packs whose full workflow is
	// injected ("coding+red-team"), or just "coding" when none are active
	// (§8.2, §9.1).
	Packs string
	// Model is the pinned model ID in force.
	Model string
	// Provider is the degraded-provider marker ("no api key", "provider
	// unavailable"), empty when the provider is healthy or untried. It warns
	// that a prompt will fail on demand (§1 "fail on demand", §9.1).
	Provider string
	// Targets is the in-scope target summary while engagement mode is active
	// ("scope 10.0.0.0/24,…"); empty in safe mode (§9.1).
	Targets string
	// Session is the current session ID, short-form.
	Session string
	// Isolation is the container enforcement level ("container" or
	// "degraded-isolation"), empty when no container is running, so the bar
	// never claims enforced egress it does not have (§5.2, §9.1).
	Isolation string
	// MCP is the connected-server summary ("mcp 2/2"), empty when the project
	// configures no MCP servers (§5.5, §9.1).
	MCP string
	// Compaction is the context-fill readout ("ctx 42%"), empty when the
	// model's context window is unknown (§4.5, §9.1).
	Compaction string
	// Cost is the session's accumulated model spend ("cost $0.0012"), empty
	// until a turn reports usage (§3.1, §9.1).
	Cost string
	// Busy is true while the loop is working a turn.
	Busy bool
}

// Config wires the stream to the application. Every field is a callback the
// app owns; the UI holds no logic beyond rendering and input.
type Config struct {
	// Status returns the status line to render, read fresh each frame.
	Status func() Status
	// Version is the running binary's version, stamped beside the startup
	// banner. Empty omits the stamp.
	Version string
	// Submit receives a non-slash input line.
	Submit func(text string)
	// Command handles a slash command and returns text to render. A non-nil
	// error is rendered as an error line.
	Command func(name, arg string) (string, error)
	// Clear resets the harness conversation when the operator runs /clear. The
	// TUI clears its own transcript; the app forgets the model context.
	Clear func()
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
	// ChoiceAllowSession runs this call and, for the rest of the session,
	// every call of the same tool that would otherwise prompt.
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
	// Subagent is the role of the subagent run that raised the card, empty
	// for the main stream (§4.2, §9.3). It is rendered as attribution.
	Subagent string
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

// subagentBlock is one subagent run as the stream renders it (§9.5): a header
// with a spinner and live preview while running, collapsible to the run's full
// transcript and report. It is a view over the persisted subagent events — it
// holds no state the session JSONL does not also hold.
type subagentBlock struct {
	runID    string
	role     string
	running  bool
	expanded bool
	frame    int
	preview  string
	lines    []string
	report   string
	failure  string
}

// toggle flips the block between collapsed and expanded.
func (b *subagentBlock) toggle() { b.expanded = !b.expanded }

// render flattens the block to stream lines: a header always, the transcript
// and report only when expanded.
func (b *subagentBlock) render(th theme) []string {
	marker, status := "▸", "done"
	if b.expanded {
		marker = "▾"
	}
	if b.running {
		status = spinnerFrames[b.frame%len(spinnerFrames)] + " running"
	}
	header := fmt.Sprintf("%s subagent %s · %s", marker, b.role, status)
	if b.preview != "" {
		header += " · " + b.preview
	}
	out := []string{header}
	if !b.expanded {
		return out
	}
	for _, ln := range b.lines {
		out = append(out, "    "+ln)
	}
	if b.failure != "" {
		out = append(out, "    "+th.fail.Render("✗ "+b.failure))
		return out
	}
	if b.report != "" {
		out = append(out, "    "+th.card.Render("─ report ─"))
		for _, ln := range strings.Split(strings.TrimRight(b.report, "\n"), "\n") {
			out = append(out, "    "+ln)
		}
	}
	return out
}

// Model is the thin chat-stream model.
type Model struct {
	cfg Config

	// styles is the active theme, auto-selected from the terminal background
	// (§9.6). dark reports which theme is in force.
	styles theme
	dark   bool

	// pending holds rendered transcript lines that are committed but not yet
	// printed to the terminal's scrollback; flush drains it.
	pending []string
	partial string
	input   []rune

	prompt *Prompt
	reply  func(string)

	// subagents maps a run key to its block, so a run's inner events fold into
	// the block its start event opened.
	subagents map[string]*subagentBlock
	// order lists the still-live blocks' run keys in start order, so the live
	// region renders them deterministically.
	order []string
	// print writes committed transcript lines above the live region. It is the
	// terminal seam: production installs tea.Println, tests capture the lines.
	print func(lines ...string) tea.Cmd
	// spinning reports whether a spinner tick is scheduled.
	spinning bool
	// bannerPlaced reports whether the startup banner has been considered.
	// Placement happens once, when the terminal width first arrives, so a
	// later resize never re-adds a banner skipped at startup.
	bannerPlaced bool

	width  int
	height int
	quit   bool
}

// New builds the UI model. The dark theme is the default until the terminal
// answers the background-color query in Init (§9.6).
func New(cfg Config) *Model {
	return &Model{
		cfg:       cfg,
		width:     defaultWidth,
		height:    defaultHeight,
		dark:      true,
		styles:    themeFor(true),
		subagents: map[string]*subagentBlock{},
		print:     func(lines ...string) tea.Cmd { return tea.Println(strings.Join(lines, "\n")) },
	}
}

// Init implements tea.Model. It asks the terminal for its background color so
// the theme can auto-select (§9.6).
func (m *Model) Init() tea.Cmd {
	return func() tea.Msg { return tea.RequestBackgroundColor() }
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.placeBanner()
		return m, m.flush()
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.styles = themeFor(m.dark)
	case tea.KeyPressMsg:
		return m.key(msg)
	case EventMsg:
		m.apply(msg.Event)
		return m, tea.Batch(m.flush(), m.spin())
	case PromptMsg:
		m.prompt = &msg.Prompt
		m.reply = msg.Reply
	case spinnerMsg:
		for _, b := range m.subagents {
			if b.running {
				b.frame++
			}
		}
		if m.hasRunningSubagent() {
			m.spinning = true
			return m, spinnerTick()
		}
		m.spinning = false
	}
	return m, nil
}

// spin schedules the spinner tick when a run is active and none is pending.
func (m *Model) spin() tea.Cmd {
	if m.spinning || !m.hasRunningSubagent() {
		return nil
	}
	m.spinning = true
	return spinnerTick()
}

// hasRunningSubagent reports whether any block is still running.
func (m *Model) hasRunningSubagent() bool {
	for _, b := range m.subagents {
		if b.running {
			return true
		}
	}
	return false
}

// placeBanner puts the startup wordmark at the top of the transcript once, on
// the first terminal width. A terminal narrower than the art skips it entirely
// — never wrapped or truncated (art-direction decision, issue #56). The lines
// are stored unstyled and tinted with theme.banner at render time. The running
// version rides to the bottom-right of the art when the terminal is wide enough
// for both.
func (m *Model) placeBanner() {
	if m.bannerPlaced {
		return
	}
	m.bannerPlaced = true
	if m.width < bannerWidth {
		return
	}
	lines := bannerLines()
	if v := strings.TrimSpace(m.cfg.Version); v != "" && m.width >= bannerWidth+versionGap+lipgloss.Width(v) {
		lines[len(lines)-1] += strings.Repeat(" ", versionGap) + v
	}
	// The banner belongs to the transcript: it prints once into scrollback.
	for _, ln := range lines {
		m.append(m.styles.banner.Render(ln))
	}
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
	case key.Code == tea.KeyTab:
		m.toggleLatestSubagent()
	case key.Code == tea.KeyEnter || key.Code == tea.KeyReturn:
		return m, m.submit()
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

// submit handles the current input line. It returns a command when the line
// asks the program to leave (/quit, /exit), so the caller can hand tea.Quit
// back to the runtime exactly as ctrl-c does; otherwise it returns nil.
func (m *Model) submit() tea.Cmd {
	text := strings.TrimSpace(string(m.input))
	m.input = nil
	if text == "" {
		return nil
	}
	if !strings.HasPrefix(text, "/") {
		if m.cfg.Submit != nil {
			m.cfg.Submit(text)
		}
		return nil
	}

	name, arg, _ := strings.Cut(strings.TrimPrefix(text, "/"), " ")
	switch name {
	case "quit", "exit":
		return tea.Batch(m.quitCmd(), m.flush())
	case "clear":
		// /clear forgets the model context and any live content, but never the
		// scrollback: committed lines are immutable (ADR-0001). The app drops
		// the conversation; the live region drops what it held (§9.4).
		m.partial = ""
		m.subagents = map[string]*subagentBlock{}
		m.order = nil
		if m.cfg.Clear != nil {
			m.cfg.Clear()
		}
		m.append("conversation context cleared")
		return m.flush()
	}
	if m.cfg.Command == nil {
		m.append("no commands are available")
		return m.flush()
	}
	out, err := m.cfg.Command(name, arg)
	if err != nil {
		m.append("! " + err.Error())
		return m.flush()
	}
	if out != "" {
		m.append(out)
	}
	return m.flush()
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
		lines = append(lines, m.styles.card.Render(fmt.Sprintf("╭─ plan approval (%d step(s))", len(p.Steps))))
		for _, step := range p.Steps {
			lines = append(lines, "│ · "+step.Tool+" "+compactJSON(step.Params))
		}
		lines = append(lines, "│ "+
			m.styles.cardKey.Render("y")+" approve   "+
			m.styles.cardKey.Render("n")+" reject")
		lines = append(lines, m.styles.card.Render("╰─"))
		return lines
	}

	if p.Kind == PromptDiff {
		header := "╭─ diff review"
		if p.Subagent != "" {
			header += " · subagent " + p.Subagent
		}
		if p.Diff != nil {
			header += " · " + p.Diff.Summary()
		} else if p.Path != "" {
			header += " · " + p.Path
		}
		lines = append(lines, m.styles.card.Render(header))
		if p.Diff != nil {
			for _, ln := range capDiffLines(p.Diff.Lines, diffViewLines) {
				lines = append(lines, "│ "+renderDiffLine(m.styles, ln))
			}
		}
		lines = append(lines, "│ "+
			m.styles.cardKey.Render("a")+" accept   "+
			m.styles.cardKey.Render("r")+" reject   "+
			m.styles.cardKey.Render("A")+" accept-all-rest-of-turn")
		lines = append(lines, m.styles.card.Render("╰─"))
		return lines
	}

	header := "╭─ permission · "
	if p.Subagent != "" {
		header += "subagent " + p.Subagent + " → "
	}
	header += p.Tool
	if risk := p.riskText(); risk != "" {
		header += " (" + risk + ")"
	}
	lines = append(lines, m.styles.card.Render(header))
	lines = append(lines, "│ params: "+compactJSON(p.Params))
	lines = append(lines, "│ "+
		m.styles.cardKey.Render("y")+" allow-once   "+
		m.styles.cardKey.Render("a")+" allow-session   "+
		m.styles.cardKey.Render("n")+" deny")
	lines = append(lines, m.styles.card.Render("╰─"))
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
func renderDiffLine(th theme, ln diff.Line) string {
	switch ln.Op {
	case diff.OpAdd:
		return th.add.Render("+" + ln.Text)
	case diff.OpRemove:
		return th.del.Render("-" + ln.Text)
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

// View implements tea.Model. It renders only the fixed live region at the
// bottom of the terminal: still-live subagent blocks, the in-flight streaming
// partial, a live prompt card, the input line, and the status bar. Committed
// transcript lines are printed once into the terminal's own scrollback and are
// never re-rendered, so the view stays short and AltScreen stays off (ADR-0001).
func (m *Model) View() tea.View {
	var b strings.Builder

	// Still-running subagent blocks are the only transcript content that is
	// still mutable (their spinner animates and Tab can expand them), so they
	// live in the live region until their run finishes and prints.
	for _, key := range m.order {
		blk := m.subagents[key]
		if blk == nil {
			continue
		}
		for _, line := range blk.render(m.styles) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if m.partial != "" {
		b.WriteString(strings.TrimRight(m.partial, "\n"))
		b.WriteByte('\n')
	}
	for _, line := range m.promptBlock() {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(m.inputLine())
	b.WriteByte('\n')
	b.WriteString(m.statusLine())

	return tea.NewView(b.String())
}

// inputLine is the prompt with the current buffer and a block cursor.
func (m *Model) inputLine() string {
	return m.styles.prompt.Render("> ") + string(m.input) + "█"
}

// statusLine is the one-line status bar (§9.1).
func (m *Model) statusLine() string {
	status := Status{}
	if m.cfg.Status != nil {
		status = m.cfg.Status()
	}
	parts := []string{status.Mode}
	if status.Packs != "" {
		parts = append(parts, status.Packs)
	}
	if status.Model != "" {
		parts = append(parts, status.Model)
	}
	if status.Provider != "" {
		parts = append(parts, m.styles.fail.Render("⚠ provider "+status.Provider))
	}
	if status.Isolation != "" {
		parts = append(parts, status.Isolation)
	}
	if status.Targets != "" {
		parts = append(parts, status.Targets)
	}
	if status.MCP != "" {
		parts = append(parts, status.MCP)
	}
	if status.Compaction != "" {
		parts = append(parts, status.Compaction)
	}
	if status.Cost != "" {
		parts = append(parts, status.Cost)
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
	return m.styles.status.Render(text)
}

// apply renders one session event onto the stream.
func (m *Model) apply(ev sessions.Event) {
	// Subagent lifecycle events open, update, and close a collapsible block;
	// the run's inner events fold into that block rather than the main stream
	// (§4.2, §9.5).
	if ev.Kind == sessions.KindSubagent {
		m.applySubagent(ev)
		return
	}
	if ev.Subagent != "" {
		m.applySubagentEvent(ev)
		return
	}

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
		m.append(m.styles.tool.Render("  " + toolCallText(ev)))
	case sessions.KindToolResult:
		// The delegation result is the subagent block's report; rendering it
		// again here would duplicate the run.
		if ev.Tool == dispatchToolName {
			return
		}
		m.commitPartial()
		switch {
		case ev.Failure != "":
			m.append(m.styles.fail.Render("    " + toolResultText(ev)))
		case ev.Result == "":
			m.append("    " + toolResultText(ev))
		default:
			m.append(indentLines(toolResultText(ev), "    "))
		}
	case sessions.KindDiff:
		m.commitPartial()
		if ev.Diff != nil {
			m.append("  " + m.styles.diffHeader.Render(ev.Diff.Summary()))
			lines := make([]string, 0, len(ev.Diff.Lines))
			for _, ln := range capDiffLines(ev.Diff.Lines, diffViewLines) {
				lines = append(lines, "    "+renderDiffLine(m.styles, ln))
			}
			m.append(strings.Join(lines, "\n"))
		} else if ev.Path != "" {
			m.append("  diff: " + ev.Path)
		}
	case sessions.KindPlan:
		m.commitPartial()
		m.append("  " + m.styles.diffHeader.Render("plan"))
		for _, step := range ev.Steps {
			m.append("    · " + step.Tool + " " + compactJSON(step.Params))
		}
	case sessions.KindCompaction:
		m.append(m.styles.card.Render("… compacted: " + ev.Detail))
	case sessions.KindEngagement:
		m.commitPartial()
		switch {
		case ev.Engagement != "":
			m.append(m.styles.banner.Render("⚑ engagement active: " + ev.Engagement))
		case ev.Detail != "":
			m.append(m.styles.banner.Render("⚑ " + ev.Detail))
		}
	case sessions.KindIsolation:
		m.commitPartial()
		text := ev.Detail
		if text == "" {
			text = ev.Isolation
		}
		m.append(m.styles.banner.Render("⚑ " + text))
	case sessions.KindMCP:
		// MCP connection lifecycle is always visible: a server that failed to
		// launch, crashed, or disconnected must never be silent (§5.5).
		m.commitPartial()
		m.append(mcpLine(m.styles, ev))
	case sessions.KindUpdate:
		m.commitPartial()
		m.append(m.styles.card.Render("↑ " + ev.Detail))
	case sessions.KindError:
		m.commitPartial()
		m.append(m.styles.fail.Render("! " + ev.Failure))
	}
}

// mcpLine renders one MCP server lifecycle transition.
func mcpLine(th theme, ev sessions.Event) string {
	server := ev.Server
	if server == "" {
		server = "server"
	}
	switch ev.Status {
	case "ready":
		return th.banner.Render("⚑ mcp "+server+": ready") + " (" + ev.Detail + ")"
	case "failed":
		return th.fail.Render("! mcp " + server + " unavailable: " + ev.Detail)
	case "closed":
		return th.card.Render("  mcp " + server + ": closed")
	default:
		return th.card.Render("  mcp " + server + ": " + ev.Status)
	}
}

// runKey identifies a run: its unique run id, falling back to the role when a
// producer set no id.
func runKey(ev sessions.Event) string {
	if ev.RunID != "" {
		return ev.RunID
	}
	return ev.Subagent
}

// applySubagent opens, updates, or closes a subagent run's block.
func (m *Model) applySubagent(ev sessions.Event) {
	key := runKey(ev)
	if ev.Detail == "start" {
		b := &subagentBlock{runID: key, role: ev.Subagent, running: true}
		b.preview = firstLineText(ev.Text)
		m.subagents[key] = b
		m.order = append(m.order, key)
		return
	}
	b := m.blockFor(key)
	if b == nil {
		return
	}
	b.running = false
	switch {
	case ev.Failure != "":
		b.failure = ev.Failure
		b.preview = firstLineText(ev.Failure)
	case ev.Text != "":
		b.report = ev.Text
		b.preview = firstLineText(ev.Text)
	}
	// The run is finished, so its printed form is final: commit the block to
	// scrollback and drop it from the live region. Before this moment Tab can
	// expand it; afterwards the printed lines are immutable (ADR-0001, spec
	// "scrollback is the pager").
	m.append(strings.Join(b.render(m.styles), "\n"))
	m.retire(key)
}

// retire removes a finished block from the live region.
func (m *Model) retire(key string) {
	delete(m.subagents, key)
	for i, k := range m.order {
		if k == key {
			m.order = append(m.order[:i], m.order[i+1:]...)
			return
		}
	}
}

// applySubagentEvent folds one of a run's inner events into its block.
func (m *Model) applySubagentEvent(ev sessions.Event) {
	switch ev.Kind {
	case sessions.KindTextDelta, sessions.KindReasoningDelta:
		// Deltas are superseded by the assembled assistant event.
		return
	}
	b := m.blockFor(runKey(ev))
	if b == nil {
		return
	}
	var rendered string
	switch ev.Kind {
	case sessions.KindAssistant:
		rendered = ev.Text
	case sessions.KindToolCall:
		rendered = toolCallText(ev)
	case sessions.KindToolResult:
		rendered = toolResultText(ev)
	case sessions.KindDiff:
		if ev.Diff != nil {
			rendered = ev.Diff.Summary()
		}
	case sessions.KindError:
		rendered = "! " + ev.Failure
	}
	if strings.TrimSpace(rendered) == "" {
		return
	}
	b.lines = append(b.lines, strings.Split(strings.TrimRight(rendered, "\n"), "\n")...)
	if preview := firstLineText(rendered); preview != "" {
		b.preview = preview
	}
}

// blockFor returns the block for a run key, nil when no run opened it.
func (m *Model) blockFor(key string) *subagentBlock {
	return m.subagents[key]
}

// toggleLatestSubagent expands or collapses the most recent still-live block.
func (m *Model) toggleLatestSubagent() {
	for i := len(m.order) - 1; i >= 0; i-- {
		if b := m.subagents[m.order[i]]; b != nil {
			b.toggle()
			return
		}
	}
}

// firstLineText returns a short one-line preview of a block of text.
func firstLineText(s string) string {
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return truncate(line, 80)
		}
	}
	return ""
}

// toolCallText renders a tool call line, shared by the main stream and a
// subagent block.
func toolCallText(ev sessions.Event) string {
	return fmt.Sprintf("· %s %s → %s", ev.Tool, compactJSON(ev.Params), verdictText(ev))
}

// toolResultText renders a tool result body, shared by the main stream and a
// subagent block. The caller supplies its own indentation and styling.
func toolResultText(ev sessions.Event) string {
	switch {
	case ev.Failure != "":
		return "✗ " + ev.Failure
	case ev.Result == "":
		return "(no output)"
	default:
		return capLines(ev.Result, viewLines)
	}
}

// verdictText renders a tool call's verdict and reason.
func verdictText(ev sessions.Event) string {
	if ev.Reason == "" {
		return ev.Verdict
	}
	return ev.Verdict + " (" + ev.Reason + ")"
}

// append queues a rendered line (or several) to be printed into the terminal's
// scrollback. Committed lines are immutable once printed (ADR-0001).
func (m *Model) append(text string) {
	if strings.TrimRight(text, "\n") == "" {
		return
	}
	m.pending = append(m.pending, strings.Split(strings.TrimRight(text, "\n"), "\n")...)
}

// flush returns the command that prints the pending transcript lines above the
// live region, or nil when nothing is pending.
//
// The lines are printed in chunks no taller than the terminal. Bubble Tea
// prints committed lines with one cursor-relative insert-above operation whose
// length is bounded by the screen height; a taller payload cannot be inserted
// and leaves its overflow as blank lines in the scrollback. Splitting the
// payload keeps each insertion within that bound, and tea.Sequence preserves
// the line order across the chunks.
func (m *Model) flush() tea.Cmd {
	if len(m.pending) == 0 {
		return nil
	}
	lines := m.pending
	m.pending = nil
	chunks := chunkLines(lines, m.width, m.height)
	cmds := make([]tea.Cmd, 0, len(chunks))
	for _, chunk := range chunks {
		cmds = append(cmds, m.print(chunk...))
	}
	return tea.Sequence(cmds...)
}

// chunkLines groups lines so no group renders taller than the terminal. A line
// is measured at the terminal width, so a wrapped line counts for its full
// rendered height. A single line taller than the terminal is emitted alone: it
// cannot be split further without altering the transcript.
func chunkLines(lines []string, width, height int) [][]string {
	if width < 1 {
		width = defaultWidth
	}
	if height < 1 {
		height = defaultHeight
	}
	limit := height - 1
	if limit < 1 {
		limit = 1
	}
	var chunks [][]string
	start := 0
	rows := 0
	for i, line := range lines {
		lineRows := renderedRows(line, width)
		if rows > 0 && rows+lineRows > limit {
			chunks = append(chunks, lines[start:i])
			start = i
			rows = 0
		}
		rows += lineRows
	}
	if start < len(lines) {
		chunks = append(chunks, lines[start:])
	}
	return chunks
}

// renderedRows is the number of terminal rows a line occupies at the given
// width, accounting for wrapping.
func renderedRows(line string, width int) int {
	w := lipgloss.Width(line)
	if w <= width {
		return 1
	}
	return (w + width - 1) / width
}

// commitPartial folds a live partial answer into the transcript.
func (m *Model) commitPartial() {
	if m.partial == "" {
		return
	}
	m.append(m.partial)
	m.partial = ""
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
