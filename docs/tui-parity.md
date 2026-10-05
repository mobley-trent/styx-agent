# styx-agent — v1.x TUI-parity spec (decided)

**Status:** decided. Resolves wayfinder ticket
[#59 Decide styx's TUI-parity scope](https://github.com/mobley-trent/styx-agent/issues/59),
on map [#53](https://github.com/mobley-trent/styx-agent/issues/53). Implementation
graduates as task tickets (listed under [Graduated work](#graduated-work)).

**Inputs:** the
[pi TUI feature matrix](research/2026-10-05-pi-tui-feature-matrix.md) (research on
[#58](https://github.com/mobley-trent/styx-agent/issues/58)) and the v1 spec's
§9 Terminal UI ([spec.md](spec.md#9-terminal-ui)). This spec is the v1.x *delta* on
top of the shipped §9 TUI; it does not replace it.

**Anchor:** the "feels like a prototype" complaint. The release closes the gaps a user
notices first, in the order the research ranked them, and no more.

## The scope cut (decided)

This release closes **five ranked gaps plus two cheap wins**:

| # | Gap | Why it ranks here |
|---|---|---|
| 1 | Input line-editing + history | You cannot move the cursor or recall a previous prompt. |
| 2 | Transcript scrolling | AltScreen without a viewport means you cannot see past the current screen. |
| 3 | Markdown rendering | Assistant output arrives as raw `**bold**` and code fences. |
| 4 | Slash-command completion + pickers | Every command is type-the-id-and-hope. |
| 5 | Turn interrupt | The only way to stop work is to quit the program. |
| · | Tool-output / subagent detail (cheap win) | Capped output with no path to the rest. |
| · | Reasoning display (cheap win) | Thinking is produced and thrown away. |

Everything else the matrix marked implementable is **deferred**, not rejected: mouse
support, session tree / fork / clone, external-editor handoff, message queue while busy,
image paste, LaTeX, shell `!` passthrough, OSC 8 hyperlinks, `/export`, theme selection,
configurable keybindings, a `fullscreen` mode, and syntax-highlighted diffs. Two rows
are **out of scope** for structural reasons and stay so: remote session sharing
(needs hosted infra) and extension-authored custom UI (would reverse the declined
plugin surface).

## Rendering model (decided)

styx moves from always-`AltScreen` full-frame rendering to **incremental print with a
fixed live region**:

- **Committed transcript lines are printed once** into the terminal's own scrollback and
  are **immutable**. The terminal owns scrolling, mouse wheel, and text search.
- A **fixed live region** at the bottom holds the input editor, the status bar, the live
  prompt card, and the in-flight streaming partial. Only the live region is re-rendered
  per frame.
- `AltScreen` is dropped; stylized chat-centric UX is preserved by styling printed lines,
  not by owning a full-screen frame.

This is the keystone decision; it is recorded as
[ADR-0001](adr/0001-terminal-rendering-model.md) because it is hard to reverse and a
future reader would otherwise wonder why a rich TUI gives up its own viewport.

### Consequence: "scrollback is the pager"

Because committed lines cannot be rewritten, retroactive expand/collapse is impossible.
The detail gap is therefore closed by **printing more, not by toggling**:

- Tool results and subagent transcripts print **in full** into scrollback, so the
  terminal is the pager. The current 20-line cap and "… (n more lines)" dead-end go away.
- A **generous safety cap** with an explicit elision marker remains only for pathological
  outputs (e.g. a multi-megabyte file read), so one tool call cannot flood the scrollback.
  Elided output remains fully available in the session JSONL.
- `Tab` expands a **still-live** subagent block only; once a block is committed, its
  printed form is final.

## Gap-by-gap shape (decided)

### 1. Input line-editing + history

Replace the bare `input []rune` (backspace/escape/append only) with
`charm.land/bubbles/v2/textarea` for cursor movement, word navigation, selection, and
mid-line editing, plus a small **history ring** bound to up/down. Bubbles is already
named in spec decision #9, so no dependency posture changes.

### 2. Transcript scrolling

Solved structurally by the rendering model above. No viewport is built; the terminal's
scrollback is the transcript history. This retires the "AltScreen discards native
scrollback with no viewport to replace it — the worst of both" defect.

### 3. Markdown rendering

Assistant text (and, for consistency, printed reasoning) renders through
`charm.land/glamour/v2`, themed to match the existing dark/light schemes in
[theme.go](../internal/tui/theme.go). Fenced code, lists, tables, inline code, and links
render formatted; the raw-delta path is replaced at commit time. glamour is **v2-native**
(`charm.land/glamour/v2`, verified v2.0.1), so it does not drag lipgloss v1 in.

### 4. Slash-command completion + pickers

- Typing `/` opens an **inline fuzzy command menu** in the live region above the input,
  listing the command registry with descriptions and a selection cursor (the pi-style
  behavior reproduced in the research).
- `/model`, `/resume`, and `/theme` open **modal `bubbles/list` pickers** instead of
  printing a text list and requiring a typed id. The existing `Harness.command` registry
  is the single source for both surfaces.

### 5. Turn interrupt

`Escape` **interrupts the in-flight turn when the loop is busy**, and clears the input
line when idle. The loop already runs under a cancelable context, so this wires the
existing `runCtx` cancel to a key. `Escape` never quits; `ctrl-c`/`ctrl-d` keep their
quit meaning.

### Cheap win · Tool-output / subagent detail

See [Consequence: scrollback is the pager](#consequence-scrollback-is-the-pager).

### Cheap win · Reasoning display

Model reasoning prints **dimmed inline, default on**, and persists in scrollback as part
of the transcript. This replaces the current behavior, where `apply()` drops
`KindReasoningDelta` outside subagent blocks so reasoning is never shown.

## Dependencies (decided)

- **Added:** `charm.land/bubbles/v2` (textarea, list) and `charm.land/glamour/v2`.
- **Deferred:** `chroma` (syntax-highlighted diffs) travels with the deferred diff-polish
  item, not this release.
- Both additions are v2-native `charm.land` modules, keeping the spec-#9 stack coherent
  (`bubbletea/v2` + `lipgloss/v2`). No lipgloss-v1 downgrade.

## Priority (decided)

1. **Rendering model** (incremental print + live region) — foundational; the other work
   builds on the new print/live-region split, so it lands first and gates the rest.
2. **Input editor + history** and **turn interrupt** — the two most-felt gaps.
3. **Markdown** and **detail-as-pager** (full tool/subagent printing).
4. **Completion + pickers** and **reasoning display**.

## Graduated work

Implementation tickets, in priority order (see the map for the live frontier):

- Switch the TUI to incremental print with a fixed live region (drop AltScreen) — gates
  the rest.
- Replace the input line with a bubbles/textarea editor and history.
- Add Escape-to-interrupt for the in-flight turn.
- Render assistant text and reasoning through glamour.
- Print full tool output and subagent transcripts into scrollback (safety cap + elision).
- Add the slash-command fuzzy menu and modal list pickers.
- Display reasoning dimmed by default.

## Out of scope (this release)

The deferred tail enumerated under [The scope cut](#the-scope-cut-decided), plus the two
structural exclusions. Deferral is a scheduling choice, not a verdict; a later ticket may
promote any item.
