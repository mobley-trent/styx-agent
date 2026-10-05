# Terminal rendering model: native scrollback with a fixed live region

styx's TUI rendered every frame into a full-screen `AltScreen` buffer while also trimming
the transcript to the terminal height, so committed output was lost with no in-app
viewport to replace it. For the v1.x TUI-parity release we **drop `AltScreen`**: committed
transcript lines are printed once into the terminal's own scrollback and are immutable,
and only a fixed bottom **live region** (input editor, status bar, live prompt card,
streaming partial) is re-rendered per frame. We chose this over building a
`bubbles/viewport` because the terminal's scrollback already gives scrolling, mouse wheel,
and text search for free, matches the observed default mode of the tool we benchmarked,
and keeps styx behaving like a normal CLI.

## Considered Options

- **Keep `AltScreen`, add `bubbles/viewport`.** Would enable in-app scroll and transcript
  search, but makes styx own all scrolling behavior and still leaves the user's normal
  terminal scrollback empty. Rejected as more code for a worse fit with CLI expectations.
- **Keep `AltScreen` as-is.** The status quo; it is the defect being fixed.

## Consequences

- Committed lines cannot be rewritten. Retroactive expand/collapse of tool output or
  subagent transcripts is therefore impossible; detail is reached by **printing in full**
  into scrollback ("scrollback is the pager") rather than by toggling. See
  [tui-parity.md](../tui-parity.md).
- The input editor becomes a component (bubbles/textarea) living in the live region
  rather than hand-rolled key handling over the whole model.
- Reverse migration to a full-screen viewport model later would touch the whole view
  layer, which is why this is recorded.
