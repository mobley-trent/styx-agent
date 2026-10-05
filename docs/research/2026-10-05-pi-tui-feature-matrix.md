# Research: pi TUI feature matrix — implementable vs. not

*Wayfinder ticket: [#58 pi TUI feature matrix: implementable vs not](https://github.com/mobley-trent/styx-agent/issues/58) · Research date: 2026-10-05.*

## Method

Primary sources only:

- **Ran `pi` 0.87.1 live.** Launched under a pseudo-terminal (`script -qec`), captured the alternate-screen byte stream on a 80-column terminal. Observed the startup layout, the live status footer, and the `/` command menu.
- **Read pi's bundled source** at `~/.pi/agent/install/releases/0.87.1/node_modules/@earendil-works/pi-coding-agent` (the coding agent) and `.../@earendil-works/pi-tui` (its component library), plus pi's own docs (`docs/tui.md`, `docs/keybindings.md`, `docs/slash-commands.md`, `docs/settings.md`).
- **Read styx's own TUI source** (`internal/tui/tui.go`, `internal/tui/theme.go`, `internal/app/run_tui.go`) and `go.mod`.

pi version observed: `pi 0.87.1`; footer read `(deepseek) deepseek-flash • high`, context `0.0%/1.0M (auto)`.

## Observed live behavior

Startup renders (80 cols):

```
 pi v0.87.1
 escape interrupt · ctrl+c/ctrl+d clear/exit · / commands · ! bash · ctrl+o
 more
 Press ctrl+o to show full startup help and loaded resources.
 ...
[Skills]
  api-security-testing, ...
────────────────────────────────────────────────────────────────
                              (input line)
────────────────────────────────────────────────────────────────
/tmp
0.0%/1.0M (auto)              (deepseek) deepseek-flash • high
```

Typing `/` opens a **searchable command menu** (73 entries in this install), showing a `→` selection cursor, per-entry descriptions, and `(1/73)` pagination. So autocomplete is not a claim from docs — it was reproduced.

## Feature matrix

Verdict legend: **have** = styx already does it; **can** = implementable in styx's stack (Go + Bubble Tea v2 / Lip Gloss v2); **can't** = not without new infrastructure or a scope reversal (reason given).

| Capability | pi 0.87.1 (primary source) | styx today (source) | Verdict |
|---|---|---|---|
| Slash-command autocomplete | Typing `/` opens a fuzzy command menu (observed: 73 cmds, `(1/73)`); `pi-tui/autocomplete.js` + `SelectList`; docs describe it as the live command reference | `/` is parsed on Enter only (`submit()` in `internal/tui/tui.go`); commands listed as static text in `helpText` (`internal/app/run_tui.go`) | **can** — a command registry already exists (`Harness.command`); needs a completion popup |
| Transcript scrolling | Default `regular` mode: terminal owns scrollback. `fullscreen` mode: `ScrollView` with pageUp/pageDown, half-page, line, home/end, **transcript search** (`ctrl+shift+f`), jump between prompts (`tui.altScreen.*`) | `v.AltScreen = true` **and** `tailLines(body, height)` — the viewport is trimmed to terminal height, so AltScreen discards native scrollback with no viewport to replace it | **can** — either drop AltScreen (keep native scrollback) or add a viewport; today it is the worst of both |
| Markdown rendering | `Marked` + custom strict-strikethrough tokenizer + LaTeX in `pi-tui/components/markdown.js`; assistant text renders through the `Markdown` component (`assistant-message.js`) | Assistant text is appended verbatim (`KindAssistant → m.append(ev.Text)`); no renderer | **can** — `glamour` is the lipgloss-native Go equivalent |
| Configurable keybindings | `keybindings.json` maps action ids (`tui.editor.*`, `app.*`) to keys; `/hotkeys` lists them; `KeybindingsManager` | Hardcoded `switch` in `Model.key()` | **can** — scope question, not a capability gap |
| Input line-editing | `Editor` + `kill-ring.js`, `undo-stack.js`, `word-navigation.js`: cursor movement, word nav, delete word/line, yank/pop, undo, selection, jump-to-char | `input []rune` with only backspace, escape-clears, and append — **no cursor movement or mid-line edit at all** | **can** — `bubbles/textarea`, or hand-rolled; the current gap is severe |
| Input history | `tui.editor.cursorUp/Down` browse history; dedicated `historyPrevious/Next` actions | None | **can** |
| Interactive pickers | `SelectList` / `SettingsList`: `/model`, `/resume`, `/tree`, `/settings`, `/theme`, all keyboard-driven | Commands print text lists and require typing an id (`/model <id>`, `/resume <id>`) | **can** — `bubbles/list` |
| Mouse support | Fullscreen routes normalized mouse events; wheel scrolls the nearest `ScrollView`; drag selects; OSC 8 links take precedence | None | **can** — Bubble Tea v2 mouse mode |
| Turn interrupt | `escape` = `app.interrupt` (cancel/abort) | `escape` clears input; only `ctrl+c`/`ctrl+d` (which quit) stop work | **can** — the loop already runs under a cancelable context |
| Reasoning / thinking display | Thinking blocks with `ctrl+t` collapse/expand; `thinking-selector`; 43 `thinking` refs in `interactive-mode.js` | `sessions.KindReasoningDelta` exists but `apply()` drops deltas outside subagent blocks | **can** |
| Tool-output expand/collapse | `ctrl+o` (`app.tools.expand`) expands tool output | `capLines(…, 20)` prints `… (n more lines)` with **no expand path** | **can** |
| Diff rendering | `diff` lib + syntax highlighting (`highlight.js` referenced in `interactive-mode.js` and `theme.js`) | ± colored lines, capped at 40, no syntax highlight | **partly / can** — `chroma` for highlighting |
| External editor | `ctrl+g` opens `$VISUAL`/`$EDITOR` | None | **can** |
| Image paste / inline images | `ctrl+v` pastes an image; `Image` component; `photon-node` for resize | None | **can, effortful** — terminal graphics protocol + platform clipboard |
| Message queue while busy | `alt+enter` queues a follow-up; `alt+up` restores it | `submit()` drops input when `busy` (CompareAndSwap fails → silent no-op) | **can** |
| Session tree / fork / clone | `/tree`, `/fork`, `/clone`, plus a searchable `/resume` picker | `/resume <id>` text list only; no tree/fork/clone | **can** — the session store exists |
| Export / share | `/export` HTML/JSONL; `/copy`; `/share` uploads to a hosted viewer | Sessions persist as JSONL; no export UI | export **can**; share **can't without a hosted service** |
| Theme selection | Theme JSON files, `theme-selector`, `/settings` | One dark + one light theme, auto-selected from terminal background (`theme.go`) | **partly / can** |
| Fullscreen vs. regular mode | `tuiMode` setting, default `regular`; `fullscreenScrollbar`, exit output | Always AltScreen | **can** |
| Status / footer | Footer with context %, model, thinking level; dynamic border | Already a rich one-line status bar | **have** |
| Shell `!` passthrough | `!` prefix runs bash inline in the editor | `bash` is a model tool only | **can** |
| OSC 8 hyperlinks | Hyperlink rendering in the component library | Lip Gloss v2 supports hyperlinks; unused | **can** |
| LaTeX math | `latex.js` tokenizer | None | **can, custom** — no Go drop-in mirrors pi's tokenizer |
| Extension-provided UI (`ctx.ui` select/confirm/input/editor, overlays, widgets, custom screens) | Full extension UI API; extensions can replace header/footer/editor and draw overlays | No extension UI surface; the capability roadmap already **declined policy-bypassing plugins** | **can't by design** — would reverse a decided scope boundary |
| Remote session sharing (`/share` viewer link) | Uploads the session to earendil's service | No service, and styx's posture is self-hosted/OSS | **can't without new infra** (likely out of scope) |

## What cannot be implemented (and why)

Only two rows fail for a **structural** reason, not a coding-effort reason:

1. **Remote session sharing / viewer links.** pi's `/share` depends on a hosted service styx does not have. A styx equivalent means standing up infrastructure, which is beyond this map's destination. Treat as out of scope unless redrawn.
2. **Extension-authored custom UI.** pi lets extensions replace the editor/header/footer and draw overlays. Adopting it would reintroduce exactly the policy-bypassing plugin surface the capability-gap research (map decision on [#60]) recommended declining. Building a *safe, policy-mediated* UI surface is possible, but it is a new architecture decision, not a TUI-parity port.

Everything else is **implementable in Go / Bubble Tea v2 / Lip Gloss v2**. The honest caveats are effort and new dependencies, not feasibility:

- styx currently depends only on `bubbletea/v2` and `lipgloss/v2` (`go.mod`). Markdown, viewport, list, and syntax highlighting each add a dependency (`glamour`, `bubbles/viewport`, `bubbles/list`, `chroma`).
- Markdown and LaTeX are not byte-for-byte portable from pi: glamour differs from `marked`, and pi's LaTeX tokenizer has no Go equivalent. "Can implement", not "can copy".
- Inline images and clipboard paste are terminal- and OS-dependent; feasible but the most platform-sensitive items.

## Hardest gaps, ranked (input for the TUI-parity decision)

If the TUI-parity ticket wants the "feels like a prototype" complaint addressed, these are the gaps a user notices first, in order:

1. **Input editing + history** — you cannot move the cursor or recall a previous prompt.
2. **Transcript scrolling** — AltScreen without a viewport means you cannot see past the current screen.
3. **Markdown rendering** — assistant output arrives as raw `**bold**` and code fences.
4. **Slash-command completion + pickers** — every command is type-the-id-and-hope.
5. **Turn interrupt** — the only way to stop work is to quit.

The rest (mouse, expand/collapse, thinking display, external editor, message queue, session tree, theming, images) is real but lower in perceived severity.

## Cross-references

- Map: [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)
- Sibling research (declined plugin surface): capability-gap findings on branch `research/capability-gap` (`docs/research/2026-10-05-capability-gap-opencode-pentestcode-strix.md`).
- Feeds: [#59 Decide styx's TUI-parity scope](https://github.com/mobley-trent/styx-agent/issues/59).
