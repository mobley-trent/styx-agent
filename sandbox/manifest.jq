# Generate the toolset manifest and the build information from sandbox/image.json.
#
# Both files are renderings of the one pinned input set, so "what is in the
# image" has exactly one declaration (docs/sandbox-image.md §2.1, §4.2, §9).
# Deterministic: sorted keys, no clock, no environment, so the static check can
# regenerate both and compare them byte for byte with the built image's copies.
#
#   jq -S -f manifest.jq \
#     --arg toolset_sha "$(sha256sum toolset.json | cut -d' ' -f1)" \
#     --arg req_sha "$(sha256sum requirements-semgrep.txt | cut -d' ' -f1)" \
#     image.json
#
# Emits {toolset, build_info}. The toolset does not embed its own hash, so the
# first pass may pass an empty $toolset_sha; the second pass records the real
# one in build_info.

. as $root
| {
    toolset: {
      schema_version: 1,
      image_version: $root.image_version,
      base: "\($root.base.ref)@\($root.base.digest)",
      tools: [
        $root.tools[]
        | { name: .name, version: .version, parser: .parser }
      ],
      wordlists: [
        $root.wordlists[]
        | { name: .name, path: .path, sha256: .sha256 }
      ],
      data: {
        nuclei_templates: $root.data.nuclei_templates.tag,
        semgrep_rules: $root.data.semgrep_rules.commit,
        trivy_db: $root.data.trivy_db.digest,
        trivy_java_db: $root.data.trivy_java_db.digest,
        seclists: $root.data.seclists.commit
      }
    },

    build_info: {
      schema_version: 1,
      image_version: $root.image_version,
      source_date_epoch: $root.source_date_epoch,
      base: { ref: $root.base.ref, digest: $root.base.digest },
      builder: {
        ref: $root.builder.ref,
        tag: $root.builder.tag,
        digest: $root.builder.digest
      },
      # Every apt package, exact version: the package set is the tool set plus
      # the runtimes and utilities the session needs.
      apt: (
        [
          $root.tools[]
          | select(.package != null)
          | { package: .package, version: .package_version }
        ]
        + [
          $root.supporting[]
          | { package: .package, version: .package_version }
        ]
      ),
      tools: [
        $root.tools[]
        | {
            name: .name,
            version: .version,
            package: .package,
            package_version: .package_version,
            source: .source
          }
      ],
      # The one tool installed from upstream instead of a Kali package: pinned
      # by a fully hash-locked requirements file (§2.1's "pinned upstream release").
      upstream: [
        {
          name: "semgrep",
          version: ($root.tools[] | select(.source == "pypi") | .version),
          source: "pypi",
          requirements: $root.semgrep_requirements,
          requirements_sha256: $req_sha
        }
      ],
      wordlists: [
        $root.wordlists[]
        | {
            name: .name,
            path: .path,
            sha256: .sha256,
            url: .url,
            seclists_commit: $root.data.seclists.commit
          }
      ],
      data: {
        nuclei_templates: $root.data.nuclei_templates,
        semgrep_rules: $root.data.semgrep_rules,
        trivy_db: $root.data.trivy_db,
        trivy_java_db: $root.data.trivy_java_db,
        seclists: $root.data.seclists
      },
      toolset_sha256: $toolset_sha
    }
  }
