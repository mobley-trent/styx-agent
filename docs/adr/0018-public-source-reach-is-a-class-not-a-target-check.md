# Public-source reach is authorized as a class, never by the target pool

v1.3 item 12 adds a web search tool (`docs/web-search-and-osint.md`, #149). A query has no
destination: the model passes text, the harness sends it to a search provider, and text comes
back. `policy.Call.ScopeTargets` — the one way the harness learns where a call intends to go — is
empty by construction, so spec §6.2's scope check has nothing to check. The call is targetless,
and a targetless call resolves through the rule table with no scope question in either mode.

The obvious reading is that a read-only, target-free tool is safety-neutral and can be allowed
everywhere. It cannot. A query is model-authored text that leaves the operator's machine for a
third party, and inside an engagement that text routinely names the target: the pool entry, the
resolved hostname, the operator's identity provider. Scope authorizes *actions against the
target*; it says nothing about *disclosure about the target*, and the two must not be conflated.
An entry in `targets` is a host styx may act on, not a host it may tell a vendor about.

We therefore add one call class beside `ExploitClass`. **`Call.PublicReach` marks a call that
reaches a host the engagement does not authorize, on the run's behalf.** It is true for
`web_search` and for nothing else in v1.3. The engagement file gains one optional ROE flag,
**`osint_allowed`** (bool, absent = forbidden), and `ROE.Check` hard-denies a `PublicReach` call
while it is false. When it is true, the call resolves through the rule table — `allow` in
engagement mode, `prompt` in safe mode — and a `PublicReach` call counts as network for
`time_window`, so a windowed engagement does not search outside its hours.

The harness does not inspect the query. It knows the pool entries and could refuse a query that
mentions one, but OSINT on the target is the capability, not an abuse of it, and a substring
filter is both bypassable and hostile to the feature. The disclosure is authorized once, in
writing, by the human who owns the engagement; the audit records each query verbatim as the
record of what left the machine.

## Considered Options

- **Rule table only — `prompt` in safe mode, `allow` in engagement mode, no new flag.** The
  smallest change, and it matches how `dispatch_subagent` was settled (ADR-0016). Rejected: an
  engagement-mode auto-allow means the model's own query text leaves the machine with no human
  ever having written down that it may. ADR-0007's premise is that non-interactive authority
  comes only from what a human wrote before the run, and a targetless tool has no scope match to
  stand in for that writing.
- **Allow everywhere; it is read-only and touches no target.** Rejected on the same ground, plus
  one more: in safe mode nothing is authorized at all, so a standing allowance would be the one
  network capability granted without an engagement. `web_fetch` prompts there, and a search is
  not less consequential than a fetch.
- **Apply the engagement's target pool to the hosts that come back.** Superficially conservative.
  Rejected: a result's host is not a destination styx will contact, so this refuses *information*
  rather than an action — it would drop every public advisory, CVE record, and vendor page while
  still sending the query out, which is the disclosure it claims to prevent.
- **A per-host OSINT allowlist (`osint_domains`).** Would let an operator say "these sources are
  fine". Rejected: the provider resolves and fetches on its side and returns arbitrary URLs, so
  the list constrains nothing enforceable; it would be a prompt-level posture dressed as a gate.
- **Refuse search inside engagements entirely.** Cleanest boundary, and it keeps every target
  identifier on the machine. Rejected: it removes the capability from the only mode where it
  matters, and it pushes operators to skim results in a browser outside the harness, where
  nothing is audited at all.

## Consequences

- **Existing engagement files keep loading.** The flag is optional because requiring it would
  refuse every file already written; absence is unambiguous because the restrictive value is the
  default, exactly as `exploitation_autonomy` handles it (ADR-0012). A denied search names
  `roe.osint_allowed`, so the refusal is actionable rather than mysterious.
- **The denial is hard, not promptable.** It arrives through `ROE.Check`, before the rule table,
  so no project overlay and no operator prompt can widen it — the same standing-limit shape as
  `exploit_allowed` (spec §6.3).
- **One class, not one tool.** The public-source read that `docs/web-search-and-osint.md` §6
  defers would set `PublicReach` too. Giving a future public-read tool its own gate would fork
  the concept and let two mechanisms disagree about what the operator authorized.
- **No per-query granularity, deliberately.** An operator cannot authorize "search, but never
  about the SSO domain". Query text is not inspectable in any way that would hold, and pretending
  otherwise would be a filter that reports safety it does not provide.
- **What left the machine is legible afterwards.** Each query is audited verbatim as a
  `PublicReach` verdict with its reason, so an engagement's disclosure history is reconstructable
  from the audit rather than inferred from the transcript.
