# styx — the findings export

Decided by [#114 Decide the structured findings artifact](https://github.com/mobley-trent/styx-agent/issues/114)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
delivering the structured-output half of the roadmap's headless/CI capability
([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 5).
Companion to [`docs/headless-ci.md`](headless-ci.md), which decides the run itself.
Keystone rationale: [`docs/adr/0008-findings-exports-render-state-not-the-run.md`](adr/0008-findings-exports-render-state-not-the-run.md).

The rest of the CI surface is decided beside this document and is not repeated here: the run's
shape, streams, and end conditions ([#113](https://github.com/mobley-trent/styx-agent/issues/113),
[`docs/headless-ci.md`](headless-ci.md)), the severity gate and its exit codes
([#115](https://github.com/mobley-trent/styx-agent/issues/115)), diff scoping
([#116](https://github.com/mobley-trent/styx-agent/issues/116)), the USD budget cap
([#117](https://github.com/mobley-trent/styx-agent/issues/117)), and the sandbox image
([#118](https://github.com/mobley-trent/styx-agent/issues/118)).

## 1. Scope

Engagement state already holds the truth. A finished run therefore renders it, in three
machine-readable forms, and adds no fact of its own:

- **Nothing is computed that is not stored.** No new severities, no scores, no remediations, no
  narrative.
- **The export is not a second record.** It is a view of the store at the moment the run ends, and
  it is written to disk rather than kept (ADR-0004's discipline, arriving at a file).
- **The export never states a verdict.** Whether the run failed on severity is the gate's decision
  ([#115](https://github.com/mobley-trent/styx-agent/issues/115)), taken *after* the export is
  written, and no export field anticipates it.

## 2. Which findings: the reportable predicate

One predicate decides what an export carries, and the same predicate is what the severity gate
reads. There is exactly one definition of "a finding this run reports":

> **reportable** = `active` **and** `status` ∈ {`detected`, `confirmed`, `risk_accepted`}
> **and** `verification` ≠ `refuted`

- **`risk_accepted` is reportable.** It is a real finding someone consciously accepted; a CI reader
  should see it, and its `status` travels in the record so the gate can decide to exclude it. That
  call belongs to [#115](https://github.com/mobley-trent/styx-agent/issues/115), not here.
- **`false_positive`, `fixed`, and inactive records are omitted**, and the omission is counted
  twice: in the JSON envelope (`counts.omitted`) and on stderr (`styx: export 4 findings · 3
  omitted`). An omission is never silent.
- **This is not `Status.IsOpen()`.** The store's helper covers `detected` and `confirmed` only; the
  predicate above is the reporting predicate, and it is named once, in code, so the artifact and the
  gate cannot drift apart.

## 3. The JSON record — `vulnerabilities.json`

The primary machine record: the export in full, with nothing resolved away.

### 3.1 Envelope

```json
{
  "schema_version": 1,
  "engagement": "acme-q4",
  "findings": [],
  "counts": { "reported": 0, "omitted": 0 }
}
```

- **`schema_version`** starts at `1` and is **independent of the store's** `schema_version` (an
  artifact format is not a store format). A change to the shape is a v2, decided, never inferred by
  a reader.
- **`engagement`** is the engagement's `name:`, or `null` for a safe-mode run — which has no store
  and therefore exports a valid, empty document (§5).
- **`counts`** makes §2's omission visible in the machine record, not only on stderr.

### 3.2 A finding

```json
{
  "id": "finding-cccc",
  "title": "SMB signing disabled",
  "severity": "high",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "status": "confirmed",
  "confidence": "high",
  "verification": "unverified",
  "affected": [
    {
      "kind": "service",
      "host": "10.0.0.33",
      "hostname": "web02",
      "port": 445,
      "proto": "tcp",
      "product": "microsoft-ds"
    }
  ],
  "evidence": {
    "count": 2,
    "items": [{ "kind": "artifact", "ref": ".styx/out/nmap-20261030T1012.xml" }]
  },
  "first_seen": "2026-10-30T10:12:04Z",
  "last_seen": "2026-10-30T11:40:51Z"
}
```

Rules:

- **`affected` is resolved, never a bare ref.** A `host` ref becomes its primary address and
  hostname; a `service` ref becomes its host's address, port, proto, product, and version. An
  artifact is read outside styx, where `host-4a1f` means nothing.
- **A ref that does not resolve** (a deactivated or missing endpoint) is carried as
  `{"kind": "unknown", "ref": "host-9999"}` rather than dropped. Losing an affected endpoint
  silently would make a finding look narrower than the record says.
- **Evidence is a count and a list of `{kind, ref}`** — never inline excerpts. Raw output stays in
  the artifact the evidence cites.
- **`cvss_vector` appears only when the store holds one.**
- **Timestamps are the record's own** (`first_seen`, `last_seen`), carried as RFC 3339 UTC. They
  are state, so they are deterministic (§4). `created_at`/`updated_at` are record bookkeeping and
  stay out.

### 3.3 What is deliberately absent

- **No provenance stamps** (session ids, subagent attribution, model/tool authorship).
- **No credentials, secrets, or access records** — nothing that would turn an uploaded artifact into
  a leak.
- **No attack-path context.** Paths are advisory, target-specific, and computed on read (ADR-0006);
  a finding has no single target to price, and CI does not act on the hint. An export that carried a
  cost would be a second, staler ranking.
- **No host inventory.** Hosts appear only as resolved coordinates inside a finding. The store is
  the inventory; a scan's job is not to republish the network map.
- **No run metadata**: clock, duration, exit code, turn count, token spend (§4).

## 4. Determinism

**Identical state produces byte-identical artifacts**, in all three formats. A diff between two
exports then means the security posture changed, which is the only reason a CI diff is worth
anything.

- **No wall clock anywhere in an export** — no `generated_at`, no invocation times, no durations,
  and no exit code (it does not exist yet at write time, §1). The run's clock reaches the stderr
  summary and the audit trail, which already carry it.
- **Record timestamps stay**, because they come from the store: the same state yields the same
  values.
- **Order is total and declared.** Findings sort by severity (critical → info), then title, then
  joined affected endpoints, then id. Rules sort by rule id. Nothing iterates a map.
- **Serialization is fixed**: two-space indented JSON with a trailing newline; LF line endings in
  CSV and SARIF; keys in the declared struct order.

## 5. Emission: the flag, the set, and when

**`--out <dir>`**, a CI-shaped flag in [`docs/headless-ci.md`](headless-ci.md) §2.2's sense: given
**without `-n`, it is a usage error (`2`)**, never silently ignored.

- **Absent ⇒ nothing is written.** A run that is not feeding a pipeline does not litter.
- **The directory is created if missing**, and holds exactly three files:
  `vulnerabilities.json`, `vulnerabilities.csv`, `findings.sarif`.
- **All three or none.** Each is written to a temporary file in the destination directory and renamed
  into place; a failure part-way removes the set and **fails the run** (`1`). A pipeline that asked
  for an export never receives a half-written one.
- **Written on every exit path that has a loaded store**: the turn returned, the turn errored, the
  run was interrupted and torn down. Not written on a usage error (`2`) or a startup refusal (§5.2
  of the non-interactive decision), because there is no store to render.
- **A safe-mode run writes a valid empty export** (`"engagement": null`, `"findings": []`): the
  engagement store does not exist outside engagement mode, and an empty document is still the honest
  answer. A clean run leaving no artifact at all would be indistinguishable from one that never ran.
- **`--out` does not reuse `.styx/out/`.** That directory belongs to parser **Artifact**s
  ([`docs/parser-tool-contracts.md`](parser-tool-contracts.md)), is gitignored on activation, and
  mixing reports into it would blur a distinction this document exists to keep (§8). styx also does
  not gitignore the operator's `--out` directory: where output goes, and whether it is committed, is
  the operator's call.
- **The export is written before the run's exit status is decided.** The gate ([#115]) reads the
  written file; the file never records the gate's verdict.

## 6. CSV — `vulnerabilities.csv`

There is no universal vulnerability-CSV standard. The nearest concrete import contract is
DefectDojo's generic findings CSV, so styx matches its exact, case-sensitive column names where they
apply and adds its own where they do not.

```
Date,Title,Severity,Url,Id,Status,Confidence,Verification,EvidenceCount
2026-10-30T11:40:51Z,SMB signing disabled,High,10.0.0.33:445/tcp,finding-cccc,confirmed,high,unverified,2
```

- **One row per finding × affected endpoint.** A finding with three affected services is three rows.
  A finding with no resolvable endpoint is one row with an empty `Url`.
- **`Severity` is spelled as DefectDojo spells it**: `Critical`, `High`, `Medium`, `Low`, `Info`.
- **`Url` is the endpoint** — `address:port/proto` for a service, `address` for a host — or the raw
  ref when it did not resolve.
- **`Date` is `last_seen`** (RFC 3339 UTC), so a re-scan moves it.
- **Quoting is RFC 4180** (quote when the value holds a comma, quote, or newline), terminators are
  LF, and rows follow §4's order.

## 7. SARIF 2.1.0 — `findings.sarif`

A SARIF log is what a consumer that speaks SARIF expects; it is a *projection* of §3, not a second
opinion. One run, `run.tool.driver` describing styx, one result per reportable finding.

### 7.1 Driver and rules

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "styx",
          "semanticVersion": "0.4.0",
          "informationUri": "https://github.com/mobley-trent/styx-agent",
          "rules": [
            {
              "id": "smb-signing-disabled",
              "name": "SMB signing disabled",
              "shortDescription": { "text": "SMB signing disabled" }
            }
          ]
        }
      },
      "results": []
    }
  ]
}
```

- **`ruleId` is a slug of the finding's title.** The store holds no CVE/CWE registry, so the rule is
  the class of thing found, not a catalogue entry: lowercase ASCII, runs of non-alphanumerics folded
  to `-`, trimmed; a slug collision between two titles takes `-2`, `-3` in sorted-title order.
- **One rule per distinct title in the export**, with `shortDescription` = the title and **no
  `help`/`helpUri`/remediation prose** (§9).
- **`security-severity` is not emitted.** GitHub reads it as **rule-level** metadata while styx's
  severity is **per finding**; one rule serving a `high` and a `medium` finding would have to
  publish a number that is wrong for one of them. A missing score is honest; a wrong one is not, and
  GitHub falls back to `level` (§7.4).
- **`semanticVersion` is the build's version** — deterministic for a given binary.

### 7.2 A result

```json
{
  "ruleId": "smb-signing-disabled",
  "level": "error",
  "message": { "text": "SMB signing disabled" },
  "locations": [
    {
      "physicalLocation": { "artifactLocation": { "uri": "service/10.0.0.33:445/tcp" } },
      "properties": {
        "host": "10.0.0.33",
        "hostname": "web02",
        "port": 445,
        "proto": "tcp",
        "product": "microsoft-ds"
      }
    }
  ],
  "properties": {
    "findingId": "finding-cccc",
    "severity": "high",
    "status": "confirmed",
    "confidence": "high",
    "verification": "unverified",
    "evidenceCount": 2
  },
  "fingerprints": { "styxFindingV1": "9b1f3c7a5d2e4f60" },
  "partialFingerprints": { "styxFindingV1": "9b1f3c7a5d2e4f60" }
}
```

- **One result per finding**, carrying **all** its resolved endpoints as `locations`, so a
  multi-endpoint finding stays one alert.
- **`message.text` is the title.** No narrative, no remediation (§9).

### 7.3 Locations for something that is not a file

SARIF permits results without locations; GitHub needs one to display an alert, prefers
repository-relative URIs, and rejects an upload whose artifact URI **scheme** differs from the
supplied source root. So:

- **`physicalLocation.artifactLocation.uri` is a scheme-less, relative-shaped path**:
  `host/<address>` for a host, `service/<address>:<port>/<proto>` for a service (hostname when the
  address is unknown).
- **The real structure lives in the location's `properties`** — a scanner-specific bag is exactly
  what SARIF's `properties` is for, and `logicalLocations` is for program constructs, not hosts.
- **A finding with no resolvable endpoint has no `locations`**, which the spec allows.
- **Consequence, stated plainly:** GitHub will treat these locations as outside the repository and
  may decline to display them. The JSON (§3) is the primary machine record; SARIF is offered for
  consumers that accept non-file results. styx does not bend the record to fit a linter's model.

### 7.4 `level`

| severity | level |
|---|---|
| `critical`, `high` | `error` |
| `medium` | `warning` |
| `low`, `info` | `note` |

**Verification and confidence never move `level`.** A `detected`, `unverified` critical is still
critical: quietly re-ranking a finding is the silent downgrade the safety model exists to refuse.
Both travel in `properties`, and `refuted` cannot appear at all (§2).

### 7.5 Fingerprints

Both `fingerprints` and `partialFingerprints` carry the same key, `styxFindingV1`: a 16-hex-character
digest of the store's own natural key — the title and the sorted affected refs, joined by U+001F.
Emitting it twice costs nothing and serves consumers that read either property.

- **The natural key is the identity the store already dedupes on**, so the fingerprint is stable
  across re-scans of the same finding.
- **Adding an affected endpoint changes the fingerprint** and opens a new alert. That is the natural
  key doing its job, not a defect.
- **`primaryLocationLineHash` is not fabricated.** GitHub's documented dedupe key needs a source
  line, which a host finding does not have; inventing one would put a meaningless value in a field
  other tools trust.

### 7.6 What SARIF does not get

- **No `invocations`.** `exitCode` does not exist when the export is written (§1), `executionSuccessful`
  means "the tool ran" rather than "the scan found nothing", and `startTimeUtc`/`endTimeUtc` would
  break §4. A field that can only be filled dishonestly is left out.
- **No `baselineState`, no suppression files, no cross-run diffing.** Dedupe is the consumer's job,
  and the fingerprint (§7.5) is what it is given to do it with.

## 8. Naming: export, report, artifact

Three words, three things, and the export exists so they never blur:

- **Findings export** — this document's output: machine-readable records of reportable findings,
  rendered from engagement state at the end of a run.
- **Report** — v1.3's human-facing output (roadmap item 10): narrative, remediation, a viewer.
  Prose for a reader, not records for a machine.
- **Artifact** — preserved raw scanner output that a parser reads and a finding cites as evidence
  ([`docs/parser-tool-contracts.md`](parser-tool-contracts.md)). It lives in `.styx/out/` and is
  gitignored, because evidence does not belong in the repository.

## 9. Where this stops and report generation begins

**This document stops at three deterministic files over engagement state, driven by `--out`.**

Not here, and owned by v1.3's report generation: Markdown or HTML narrative, remediation prose, per-
engagement styling and templates, the local `view`/run viewer over session and audit JSONL, SARIF
baseline and suppression handling, cross-run diffing inside styx, and any `--fail-on` gating or
exit-code meaning (that is [#115](https://github.com/mobley-trent/styx-agent/issues/115)). An export
that grew a narrative would be a report; a report that emitted these files would duplicate the
rendering. One rendering, one owner.

## 10. Spec touchpoints (applied by the implementation ticket)

- **`cmd/styx`** — parse `--out <dir>`; usage error (`2`) without `-n`; document it in `usage`.
- **`internal/findingsexport`** (new, pure) — `Render(snapshot, engagement string) (json, csv, sarif
  []byte, err error)`: the reportable predicate of §2, the resolution of §3.2, the ordering and
  serialization of §4, and the three renderings. No I/O, no clock, no store access — which is what
  makes byte-identical output testable.
- **`internal/app`** — after the turn returns, on the paths §5 names, write the three files through
  temp-and-rename before the run ends; a write failure is a run failure.
- **`internal/policy`/gate** — [#115](https://github.com/mobley-trent/styx-agent/issues/115) reads
  §2's predicate from one definition, not a second copy of it.
- **Tests** — golden files per format; two renders of the same snapshot compare byte-identical; an
  empty store and a store with dangling refs; a slug collision; a `risk_accepted` finding present in
  the export and its status readable by a gate.

## 11. Explicitly not in v1.2

The severity gate and its exit codes ([#115](https://github.com/mobley-trent/styx-agent/issues/115)) ·
diff scoping ([#116](https://github.com/mobley-trent/styx-agent/issues/116)) · the USD budget cap
([#117](https://github.com/mobley-trent/styx-agent/issues/117)) · the sandbox image
([#118](https://github.com/mobley-trent/styx-agent/issues/118)) · Markdown/HTML reports and the run
viewer (§9) · SARIF baselines and suppressions (§7.6) · a machine-readable *run summary* (the
summary stays human-readable, [`docs/headless-ci.md`](headless-ci.md) §6.3) · exporting engagement
state wholesale (the store is not an artifact) · attack-path or cost context in any format (§3.3) ·
`--out` in interactive runs (a usage error) · a `styx export` subcommand over a stored engagement (a
later entry point to the same rendering, if it ever earns one).
