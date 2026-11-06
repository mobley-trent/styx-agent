# The sandbox image is content-addressed and verified before use

styx now ships a default session image (`docs/sandbox-image.md`), which means the harness is
responsible for what runs inside the container it enforces. The decision: the image is pinned by
**index digest** in the binary, and that digest's **keyless signature, signing identity, and
transparency-log inclusion** are verified against a compiled-in policy before the container is
created. Verification failure refuses the session. The one door for a custom or unverifiable image is
an explicit, audited `--allow-unverified-image` flag that accepts only digest-pinned references. The
trusted root is embedded and the verified bundle is cached, so the same check runs offline; a tag is
never resolved, and nothing about the image is inferred at runtime.

## Considered Options

- **A public image consumed by tag (`styx-sandbox:latest`).** The simplest distribution and the one
  every container tool assumes. Rejected because it makes the image mutable by whoever can push, with
  no local record of what was tested: the binary would silently run different bytes next month. A tag
  is a human convenience; it cannot be the identity of the thing the harness trusts.
- **Digest-pinned, unsigned.** Fixes mutability and is what most "pinned image" advice means. Rejected
  because a digest says *what* the bytes are, not *who* produced them: whoever controls the registry
  account can publish any digest, and a pin is only as trustworthy as the registry's access control.
  With no signature there is also no statement to verify about how the image was built.
- **Signed, verified at runtime by shelling out to `cosign`.** Matches the ecosystem's documentation
  and keeps the policy in command-line flags. Rejected as a second binary the harness must ship and
  keep in step, whose absence or version drift changes the guarantee, and whose invocation surface
  (identities, issuer, trusted root) would be assembled at runtime rather than compiled in.
- **Keyless verification in-process with sigstore-go, an embedded trusted root, and a compiled-in
  identity (chosen).** One Go dependency, no external binary, the policy in the source that a reviewer
  reads, and the bundle cached so the same verification runs disconnected. The cost is that the
  signing workflow's path is part of styx's source: renaming the workflow breaks verification until a
  styx release updates the policy — which is the correct failure direction.
- **Let configuration disable verification (an `allow_unverified_image` config key).** Considered as
  the ergonomic version of the flag and rejected: one checked-in line would opt every collaborator out
  of verification, with no prompt and no per-run decision. The flag keeps the waiver at the same
  granularity as every other widening — deliberate, attributable, audited.
- **Fail open with a warning when verification cannot run.** Rejected outright. A supply-chain check
  that degrades to a log line is not a check, and the harness's whole posture is that a safety-critical
  refusal stays fatal at startup rather than becoming a quiet default.

## Consequences

- **The image digest is a release artifact.** `scripts/sandbox-bump.sh` rewrites
  `internal/sandbox/pin.go`; the bump is reviewed like any code change, `styx --version` prints it, and
  a styx release can ship without a new image. There is no path by which the binary follows `latest`.
- **Air-gapped use costs one prepared directory.** A verified pull caches `bundle.json` and
  `toolset.json` under `$XDG_DATA_HOME/styx/sandbox/<digest>/`; the air-gap procedure is `docker save`
  plus copying that directory. A pre-pulled image without the cache is unverified, not trusted by
  existence, and the only way past it is the flag.
- **Custom images are second-class by design.** A private mirror, a vendor image, or a local build
  runs only with `--allow-unverified-image` on a digest, with a prompt and an audit entry. That is the
  intended friction: the default must be the verified image, and the exception must be visible.
- **The signing identity is a source constant.** A workflow rename, a fork, or a signature produced by
  a different ref fails verification until styx's policy is updated. The failure is loud and names the
  expected identity, which is what makes the constant safe to own.
- **The trusted root ages.** The embedded Fulcio/Rekor/CT root is refreshed on a styx release cadence;
  a root rotated upstream after a release is not trusted until the next one. Verification of older
  bundles continues to work because their certificates and log proofs are self-contained, but a
  long-lived binary cannot verify signatures from a trust domain it does not know.
- **The image's contents are verifiable, not just its bytes.** `build-info.json` and the SBOM are
  signed alongside the digest, so "which scanner versions and which trivy DB produced this" is
  answerable without rebuilding. Byte-identical rebuilds are explicitly not promised; pinned inputs
  and a failing build on drift are.
- **This is a supply-chain boundary, not a safety layer.** Scope, ROE, policy, and egress are unchanged
  and still enforced where they were. The image makes *what runs* trustworthy; it does not make what
  the model asks it to do any more permitted.
