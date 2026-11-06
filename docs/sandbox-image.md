# styx — the offensive sandbox image

Decided by [#118 Decide the offensive sandbox image](https://github.com/mobley-trent/styx-agent/issues/118)
(child of the map [Wayfinder: styx prototype → adoptable red-team agent](https://github.com/mobley-trent/styx-agent/issues/53)),
delivering the image half of the roadmap's operating surface
([`docs/red-team-roadmap.md`](red-team-roadmap.md) §1, item 4).
Keystone rationale:
[`docs/adr/0011-sandbox-image-is-content-addressed-and-verified-before-use.md`](adr/0011-sandbox-image-is-content-addressed-and-verified-before-use.md).

The rest of the v1.2 operating surface is decided beside this document and is deliberately **not**
repeated here: the non-interactive run ([#113](https://github.com/mobley-trent/styx-agent/issues/113),
[`docs/headless-ci.md`](headless-ci.md)), the findings export
([#114](https://github.com/mobley-trent/styx-agent/issues/114),
[`docs/findings-export.md`](findings-export.md)), the severity gate and exit codes
([`docs/headless-ci.md`](headless-ci.md) §8), diff scoping
([#116](https://github.com/mobley-trent/styx-agent/issues/116), deferred to v1.3), and the USD budget
cap ([#117](https://github.com/mobley-trent/styx-agent/issues/117),
[`docs/budget-cap.md`](budget-cap.md)).

Implementation graduated to
[Build and publish the offensive sandbox image](https://github.com/mobley-trent/styx-agent/issues/129)
and
[Fetch and verify the sandbox image before a session starts](https://github.com/mobley-trent/styx-agent/issues/130).

## 1. Scope

One question: **what do a session's tools run inside, and how is that image made trustworthy enough to
be the default?** Six decisions answer it — base and contents (§2), one image or a family (§3), build
and the reproducibility bar (§4), publication and pinning (§5), verification before use (§6), and the
operational consequences (§7–§10: custom images, tool data, discovery, and the pull's relationship to
egress and degraded isolation).

Four boundaries are fixed before the details:

- **The image changes the toolkit, not the enforcement.** Scope checks, ROE hard limits, the policy
  choke point, audit, and container egress all behave exactly as they do today. The image is a
  supply-chain guarantee, not a new safety layer with its own exceptions.
- **Content-addressed, never a tag.** The harness pins a digest; a tag is a human convenience that the
  harness never resolves.
- **Offline by default.** The tool data is baked at build; nothing a scan needs is fetched at runtime.
- **Nothing is inferred.** Discovery reads a manifest the image itself declares; the harness never
  probes for binaries to guess what it is running.

The harness now ships a **default** image where it previously shipped none. That is a deliberate
amendment to spec §5.1's "the harness does not build or ship images", and §11 lists the exact
touchpoints.

## 2. Base and contents

### 2.1 Base

**`kalilinux/kali-rolling`, pinned by digest, with a curated explicit package list — not a
metapackage.**

- Kali packages every scanner the parser tools understand (`nmap`, `nuclei`, `sqlmap`, `gobuster`,
  `netexec`/`bloodhound.py`) plus the roadmap's code/CI scanners (`semgrep`, `trivy`). A Debian base
  would mean tracking upstream release tarballs and their runtime dependencies for each of them.
- `kali-linux-headless` is rejected: it is a ~1.5 GB install of everything Kali considers
  GUI-free — aircrack-ng, amass, apache2, bluez, binwalk — tooling the parsers do not understand and
  the prompt cannot truthfully describe. It makes the toolset manifest a lie by omission and the
  image's value a matter of luck.
- The curated list is the same list the manifest declares (§9), so "what is in the image" has exactly
  one declaration.

| Tool | Kali package | Parser tool | Why it is here |
|---|---|---|---|
| `nmap` | `nmap` | `nmap_parse` | The substrate's primary discovery scanner; XML (`-oX`) is the parse input. |
| `nuclei` | `nuclei` | `nuclei_parse` | Template-driven vulnerability scanning; JSON Lines (`-jsonl`) is the parse input. Templates are baked (§8). |
| `sqlmap` | `sqlmap` | `sqlmap_parse` | Injection exploitation; the per-target log is the parse input. |
| `gobuster` | `gobuster` | `gobuster_parse` | Directory/DNS/vhost brute force; text output is the parse input. |
| `netexec` (`nxc`) | `netexec` | `cme_parse` | SMB/AD/LDAP/WinRM execution and enumeration; the per-target log is the parse input. Pulls `bloodhound.py` as a dependency. |
| `bloodhound.py` | `bloodhound.py` | `bloodhound_parse` | Legacy BloodHound collector JSON is the parse input. |
| `ffuf` | `ffuf` | — (`manual`) | Content discovery the gobuster parser does not model; findings enter state through `state_update` with evidence. |
| `semgrep` | `semgrep` or the pinned upstream release | — (`manual`) | Static analysis of the workspace; findings enter state through `state_update` with evidence. Rules are baked (§8). |
| `trivy` | `trivy` | — (`manual`) | Dependency, secret, and misconfiguration scanning; findings enter state through `state_update` with evidence. Databases are baked (§8). |

The three `manual` tools are shipped deliberately ahead of their parsers (roadmap item 4 names them),
and the manifest makes that visible: a tool with no parser is labelled, not quietly absent. "No parser"
means the model parses the output itself and records findings through the audited write path — a
visible, audited path, not a dead end.

**Supporting packages:** `bash`, `coreutils`, `curl`, `jq`, `git`, `python3`, `node`, `openssl`,
`ca-certificates`, `unzip`, `netcat-traditional`, the SecLists subset of §2.2, and the NSE script
directory `nmap` expects. `python3` and `node` are the guaranteed `code_exec` runtimes; `go`, `ruby`,
and `perl` are not promised by this image, and an absent one fails through the same clear
`code_exec` error it fails with today.

**Deliberately absent**, with the reasoning written down so their absence is not read as an oversight:

| Absent | Why |
|---|---|
| Metasploit, Cobalt Strike-class frameworks | Exploitation frameworks are a different capability class; the ROE's `exploit_allowed` gate governs exploit-class tooling, and a parser does not model their output. MCP may supply one later. |
| `hashcat`, `john` | Password cracking is GPU-shaped and not parser-backed; wordlists alone are shipped for the tools that use them. |
| Ghidra, radare2, Binary Ninja | Reverse engineering is v1.3's MCP surface; an RE toolchain would multiply the image size for a pack that already recommends MCP servers. |
| Volatility, forensic suites | Blue team's memory/forensic analysis is v1.3's MCP surface, for the same reason. |
| GUI or desktop packages | The session is a terminal and an exec target. |

### 2.2 Wordlists

A **curated SecLists subset**, pinned by commit — five lists totalling about 650 KB — at
`/usr/share/wordlists/styx/`, with `STYX_WORDLISTS` exported to that directory:

| List | Used for |
|---|---|
| `Discovery/Web-Content/raft-small-words.txt` | Fast first-pass content discovery (ffuf, gobuster) |
| `Discovery/Web-Content/raft-medium-directories.txt` | Second-pass directory discovery |
| `Discovery/Web-Content/common.txt` | The conventional short list |
| `Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain/vhost brute force |
| `Usernames/top-usernames-shortlist.txt` | Account enumeration seeds for AD/web flows |

- **Size:** ~650 KB in total (≈668,000 bytes at the pinned commit). These are first-pass lists: the
  exhaustive ones cost real space and belong in a bind-mount, the same reason `rockyou.txt` is not
  shipped, so the wordlist set is negligible next to the tool data.
- **Provenance and licence:** SecLists is MIT; the image carries the upstream `LICENSE` and records
  the pinned commit in `build-info.json` and in the toolset manifest's wordlist entries.
- **`rockyou.txt` is not shipped.** Its size and murky redistribution history make it a poor default;
  an operator who wants it bind-mounts it, like any other custom list.
- **Updates are image releases**, not runtime downloads. The full SecLists checkout is an operator
  bind-mount, never a container fetch.
- Each list's `sha256` is declared in the toolset manifest, so a mismatch between the image and its
  manifest is detectable rather than assumed away.

### 2.3 The in-image help text

The image ships `/etc/styx/README` (and a matching MOTD line) that names:

- the artifact directory `.styx/out/` and each scanner's output flag — `nmap -oX`,
  `nuclei -jsonl -o`, `gobuster -o`, `sqlmap --output-dir`, `netexec --log`, `bloodhound.py --zip` —
  mirroring the prompt's artifact convention
  ([`docs/parser-tool-contracts.md`](parser-tool-contracts.md) §3);
- `STYX_WORDLISTS` and the toolset manifest path;
- the offline posture: tool data is baked, so `nuclei -update-templates` and a trivy DB update will
  fail at the egress boundary by design, and updating them means a new image.

The README is a mirror, not a second source of truth: where it and the prompt disagree, the prompt
wins, and the parser contract's convention is the normative one.

## 3. One image, not a family

**One image.** Per-preset variants (web / AD / RE) are rejected for v1.2:

- The tools already share almost every layer, so the registry cost of a family is small — but local
  disk, first-run pull, and the operator's mental model all multiply by three.
- A family triples the supply chain too: three digests, three signatures, three toolset manifests,
  three verification paths, and a mapping from preset to image that has to stay truthful as presets
  evolve.
- That mapping belongs to v1.3's specialist subagents ([`docs/red-team-roadmap.md`](red-team-roadmap.md)
  §1, item 11), which is the first point at which "a web agent should not carry AD tooling" becomes a
  real capability boundary rather than an image-size preference.

Split only on evidence: a measured first-run pull that keeps being reported as a problem, or one
preset's toolset growing more than three times the rest. A split adds a variant; it never replaces the
single default. RE and forensics stay MCP-provided, so they never become image variants at all.

## 4. Build

### 4.1 Inputs and the reproducibility bar

The bar is **input-pinned and attested**, not bit-identical:

| Input | Pinned by |
|---|---|
| Base image | `kalilinux/kali-rolling@sha256:…` digest |
| Apt packages | Exact version for every package; the build fails if a pinned version is unavailable |
| Upstream binaries (where Kali's package is not used) | Version plus `sha256` of the release artifact |
| SecLists | Commit plus per-file `sha256` |
| Nuclei templates | Release tag plus archive `sha256` |
| Semgrep rules | Ruleset version plus archive `sha256` |
| Trivy vulnerability + Java DBs | DB version/timestamp plus file `sha256` |
| Builder image | Digest |
| Build clock | `SOURCE_DATE_EPOCH`, from the image version's commit timestamp |

The Dockerfile does `apt-get install --no-install-recommends` against the pinned list, never
`apt-get upgrade`, and strips caches and docs. A rebuild months later may legitimately differ because
Kali has no snapshot service to pin against; the guarantee we can actually keep is that every input
was pinned, every input is attested, and **drift fails the build instead of producing a silently
different image**. Vendoring every `.deb` into the build context for byte-identical rebuilds is
explicitly not taken on (§12): it buys reproducibility at a licence-attribution and maintenance cost
this project should not pay yet.

### 4.2 Build information

Every build emits `build-info.json`, signed and published beside the image, recording: the base
digest, every apt package and version, every upstream binary and checksum, the SecLists commit, the
data versions (templates, rules, DBs), the `SOURCE_DATE_EPOCH`, the builder image digest, and the
`sha256` of the generated toolset manifest. It is the audit trail for "what exactly produced this
digest", and the toolset manifest is a rendering of a subset of it.

### 4.3 Pipeline

`.github/workflows/sandbox-image.yml`, triggered by a monthly schedule, a manual dispatch, changes
under `sandbox/` on `main`, and pull requests touching `sandbox/**`:

- `docker/build-push-action` via buildx, multi-arch (`linux/amd64`, `linux/arm64`), pushing the
  manifest list to the registry of §5.
- **Both architectures are verified**, not merely built: the build job runs the full conformance
  check against the amd64 image, and a second job asserts the index carries both manifests before
  re-running that same check on `linux/arm64` under qemu. An arm64 layer that will not execute
  fails the pipeline instead of shipping under a signature that claims it was verified.
- **Pull requests build without publishing**: a PR touching `sandbox/**` builds the amd64 image
  under a preview version derived from the PR number and runs the same conformance check against it.
  The install, the segment downloads and the manifest generation are where a pin change goes wrong,
  so catching that on the PR costs minutes instead of a broken monthly publish.
- Provenance `mode=max` and an SBOM (`syft`/buildkit) attached as attestations.
- **Cosign keyless** signing of the **index digest** (not a tag, not a per-arch manifest), plus a
  signed SBOM attestation. The signing identity is the workflow path on `main`; it is compiled into
  styx (§6), so a workflow rename is a breaking change discovered by a failing verification, not a
  silent trust widening.
- Permissions are exactly `contents: read`, `packages: write`, `id-token: write`; no long-lived
  signing key exists anywhere.

### 4.4 Versioning and cadence

- Image versions are independent of styx: **`sandbox-v1.YYYY.MM.PATCH`**. v1 is the image contract
  (manifest schema, paths, entry points); a change to that contract is `sandbox-v2`, and styx refuses
  an image whose manifest schema it does not know rather than guessing.
- **Monthly rebuild**, plus an out-of-band rebuild for a scanner CVE or a security fix in a bundled
  tool. The monthly cadence is also what bounds trivy DB staleness (§8).
- Tags are informational. The harness pins the index digest in `internal/sandbox/pin.go`, and
  `scripts/sandbox-bump.sh` rewrites that file from a published build so the bump is an ordinary
  reviewed PR. A styx release that does not need a new image keeps the previous digest.
- `styx --version` prints the pinned sandbox digest, so "what will this binary run" is answerable
  without opening the source.

## 5. Publication

- **Registry:** `ghcr.io/mobley-trent/styx-sandbox`, public, anonymous pull. GHCR is chosen over
  Docker Hub because it has no anonymous pull-rate ceiling for this use and because the keyless
  identity already comes from the same GitHub OIDC issuer.
- **What is pinned:** the manifest-list **index digest**, e.g.
  `ghcr.io/mobley-trent/styx-sandbox@sha256:<index>`. Docker selects the platform manifest from the
  signed index, so one digest covers both architectures and trust flows from the index to the
  per-arch manifest.
- **`internal/sandbox/pin.go`** holds `Image`, `Digest`, `Version`, and the embedded toolset manifest,
  all generated by the bump script — never hand-edited.
- The SBOM, provenance, and `build-info.json` are published as attestations/release artifacts for the
  same digest; they are what a supply-chain reviewer checks, not what the harness reads at runtime.

## 6. Verification before use

### 6.1 The check

The harness verifies with **sigstore-go**, not the `cosign` binary: the trusted root (Fulcio
certificates, Rekor key, CT log) is **embedded in the styx binary**, and the policy is compiled in:

- expected OIDC issuer: `https://token.actions.githubusercontent.com`;
- expected certificate identity: the sandbox workflow on `main`
  (`https://github.com/mobley-trent/styx-agent/.github/workflows/sandbox-image.yml@refs/heads/main`);
- the signature must cover the **pinned index digest**, the certificate must chain to the embedded
  Fulcio root, the SCT must validate, and the Rekor inclusion proof must verify.

The signature bundle (`sha256-<digest>.sig`, the cosign artifact convention) is fetched from the
registry, verified against the digest, and only then is the image pulled **by digest**. Verification
therefore precedes the pull: unverified bytes are never downloaded into the daemon. With the trusted
root embedded and the bundle in hand, verification itself needs no network.

### 6.2 The trust cache

A successful verification caches, under `$XDG_DATA_HOME/styx/sandbox/<index-digest>/`:

- `bundle.json` — the signature bundle that was verified;
- `toolset.json` — the manifest read from the verified image.

Every later start re-verifies the cached bundle against the embedded root and identity — cheap, and
offline. This is the air-gap path: on a connected host, pull and verify once, then move the image
(`docker save`/`docker load`) and copy the cache directory to the disconnected host. A pre-pulled
image **without** a cached bundle is unverified, not trusted-by-existence.

### 6.3 Failure

Verification failure refuses the session at start (exit `1`), before the container, network, or
firewall exist, with a message naming the digest, the expected identity, and the actual reason. There
is no fallback image, no "run the old one instead", and no degraded mode that silently skips the
check. A custom or air-gapped image is the only reason to proceed unverified, and that is the explicit
door of §7.

A mismatch between the pinned digest's embedded toolset and the manifest inside the pulled image is
also a refusal: it means the binary and the image were built out of step, and running it would make
the prompt lie about what is installed.

## 7. Custom images and the explicit opt-out

- **`container.image` stays**, and is honored for operator-pinned images (private mirrors, a
  vendor's image, a local development build).
- **The official pinned digest is verified**; any other reference is **unverified**.
- **`--allow-unverified-image`** is the only door (a flag, never a config key). It:
  - requires a digest-pinned reference (`@sha256:…`); a tag is a usage error even with the flag;
  - prompts once at startup, naming the image and digest, and proceeds only on an explicit yes;
  - writes an audit entry recording the image, digest, and that verification was waived;
  - does **not** write the trust cache, because nothing was verified.
- **A flag and not a config key, deliberately.** A checked-in `allow_unverified_image` would let one
  commit opt every collaborator out of verification with no prompt and no per-run decision; the flag
  keeps that choice in the same class as any other widening — explicit, attributable, audited.
- **Local development** uses the same door: `docker build` the image, reference it by digest, pass the
  flag. There is no bypass that skips the prompt.
- **Toolset discovery still applies** to an unverified image (§9): if it ships a manifest, the prompt
  can describe it truthfully; if it does not, the toolset is "unknown" and the prompt says so.

## 8. Tool data and runtime network

Everything a tool needs is **baked at build**, and nothing is fetched at runtime by default:

| Data | Baked from | Refresh |
|---|---|---|
| Nuclei templates | Pinned release archive | Image release |
| sqlmap tamper scripts | The packaged sqlmap version | Image release |
| Semgrep rules | Pinned ruleset archive | Image release |
| Trivy vulnerability DB | `ghcr.io/aquasecurity/trivy-db` at build | Image release (monthly bounds staleness) |
| Trivy Java DB | `ghcr.io/aquasecurity/trivy-java-db` at build | Image release |
| Wordlists | SecLists subset (§2.2) | Image release |

The image exports `TRIVY_SKIP_DB_UPDATE=true`, `TRIVY_SKIP_JAVA_DB_UPDATE=true`,
`TRIVY_OFFLINE_SCAN=true`, and `SEMGREP_SEND_METRICS=off`, so the tools' *default* behaviour is the
offline one; no wrapper scripts rewrite their semantics. A tool that still tries to reach the network
(`nuclei -update-templates`, a manual trivy DB update) hits the session's egress boundary and fails
loudly — the README (§2.3) says so, so the failure is expected rather than a mystery.

`container.egress_allow` is unchanged and is **not** the image's upkeep mechanism: it exists for
operator-specific destinations, and the image's data never depends on it. The cost of baking is that
the tool data's date is the image's date; the monthly cadence and the visible image version are what
make that staleness legible.

## 9. Discovery

The image declares what it carries at **`/etc/styx/toolset.json`**, generated at build from
`build-info.json`:

```json
{
  "schema_version": 1,
  "image_version": "sandbox-v1.2026.11.0",
  "base": "kalilinux/kali-rolling@sha256:…",
  "tools": [
    {"name": "nmap", "version": "7.99", "parser": "nmap_parse"},
    {"name": "nuclei", "version": "3.11.1", "parser": "nuclei_parse"},
    {"name": "ffuf", "version": "2.1.0", "parser": null}
  ],
  "wordlists": [{"name": "raft-small-words", "path": "/usr/share/wordlists/styx/raft-small-words.txt", "sha256": "…"}],
  "data": {"nuclei_templates": "…", "trivy_db": "…", "semgrep_rules": "…"}
}
```

- **Read once**, after the container starts, with a single `cat` — not a `command -v` probe per tool,
  and not a set of version invocations. One read of a declaration the verified image made about
  itself.
- **For the official pinned digest**, the manifest is also embedded in the styx binary, so the toolset
  is known at startup and can ride the byte-stable system-prompt prefix (spec §3.3/§7.4) before the
  container exists. A mismatch between embedded and in-image manifests is the refusal of §6.3.
- **For a custom image**, the manifest is read when the container starts and delivered as ordinary
  turn content ("sandbox toolset: …"), never mutating the system-prompt prefix (spec §4.5).
- **Absent or malformed → "toolset unknown".** The session still runs; the prompt states that the
  toolset could not be read and names only what the harness knows (its own tool registry). It never
  infers, and it never claims a tool exists because a parser for it does.
- The prompt lists each tool with its parser mapping, so "run nmap, then `nmap_parse` it" is stated in
  the same breath; `manual` tools are marked as parsed by the model.

## 10. Pull, egress, degraded isolation, and container posture

- **The pull is harness-side plumbing, not an engagement action.** It happens at session start, before
  the container's network and firewall exist, for safe and engagement mode alike, and it is never
  model-initiated or model-selectable. It is not a tool call and does not pass the policy engine; it
  is recorded in the audit as a session-start event with the image, digest, verification result, and
  the unverified flag if set.
- **No firewall rule is involved.** The pull and the signature-bundle fetch are harness network
  operations on the host; the container's pinned egress is untouched. The only host requirement is
  reachability of the registry (and nothing else: the trusted root is embedded, so no TUF, Fulcio, or
  Rekor request is needed at verification time).
- **Degraded isolation is unchanged.** Every tool still runs behind the internal network plus the
  harness egress proxy; the baked data means the tools remain useful when the container has no
  external route, and target traffic still goes only where the pinned scope allows. The image adds no
  capability that could bypass the proxy.
- **Container posture:** the session runs as root inside the single-purpose container because Docker's
  default capability set includes `NET_RAW` and SYN-style scans need it. No `--cap-add`, no Docker
  socket, no host networking, default seccomp. Hardening beyond Docker's defaults (read-only rootfs,
  dropped capabilities with file capabilities for the scanners, a non-root user) is **not** part of
  this decision; it would need its own analysis of which tools break.
- **Docker unavailable** remains `IsolationUnavailable`, unchanged: the image does not create a
  parallel execution path.

## 11. Spec touchpoints (applied by the implementation tickets)

- **spec §5.2** — add the session-image bullet: the pinned, signed default, verified before the
  container is created; `container.image` may pin another, which runs only under the explicit audited
  flag.
- **spec §5.1** — `code_exec`'s promised runtimes are the image's (`python3`, `node`); name the
  default image.
- **spec §12.3** — the image is not an auto-updater: digest bumps are releases, never a runtime
  fetch.
- **`internal/config` `Container` comment** — "the harness ships no image" becomes "ships a verified
  default; the operator may pin another".
- **`internal/containerlayer` `DefaultImage` / `session.go` comment** — the default becomes the pinned
  digest reference, and the comment points at this document.
- **README / install docs** — the default image, the first-run pull, and the unverified-image flag.
- **`docs/parser-tool-contracts.md` §3** — the artifact convention's in-image help text now has a home
  (§2.3).
- **`docs/red-team-roadmap.md` §5** — sandbox-image contents are decided.
- **`GLOSSARY.md`** — Sandbox image, Verified image, Toolset manifest, Tool data.
- **`cmd/styx`** — `--version` prints the pinned sandbox digest.

## 12. Explicitly not in v1.2

Per-preset image variants (§3) · RE, forensics, GUI, exploitation-framework, and password-cracking
tooling (§2.1) · runtime tool-data updates (§8) · automatic digest updates, a self-updater for the
image, or the harness following `latest` (§4.4) · signing operator images or a bring-your-own-PKI
verification mode (§7) · bit-identical rebuilds via vendored `.deb` artifacts (§4.1) · a user-space
netstack for the container (spec §5.2's v1.x path) · Windows and GPU images · a `styx sandbox` command
surface, including an export subcommand — the air-gap path is a `docker save` plus a directory copy
(§6.2) · registry mirrors and proxy configuration beyond `container.image` · per-arch digests in the
pin (the index is the pin).
