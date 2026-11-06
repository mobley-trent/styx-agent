# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# The styx sandbox image (docs/sandbox-image.md).
#
# Every input is pinned in image.json, and this build fails when a pin cannot be
# satisfied instead of producing a silently different image: apt refuses an
# unavailable exact version, the dpkg loop re-checks every one, and every
# checksummed download is verified before it is unpacked. There is no
# `apt-get upgrade` and no runtime fetch: tool data is baked, so a scan needs no
# network beyond its target.
#
# Build and publish through .github/workflows/sandbox-image.yml. Never pin this
# image by tag: scripts/sandbox-bump.sh writes the published index digest into
# internal/sandbox/pin.go, and the harness resolves nothing at runtime (§5).

ARG BASE=docker.io/kalilinux/kali-rolling@sha256:7997e0581c4f5c185cfe6773d5cae8fcc7c6b79798726ccaabf843af4bcd2013

FROM ${BASE}

# bash runs the build steps; it also makes `pipefail` real for them.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

LABEL org.opencontainers.image.title="styx sandbox" \
      org.opencontainers.image.description="The pinned toolset a styx session runs in (docs/sandbox-image.md)" \
      org.opencontainers.image.source="https://github.com/mobley-trent/styx-agent" \
      org.opencontainers.image.licenses="MIT"

ARG SOURCE_DATE_EPOCH=1793923200
ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    HOME=/root \
    PATH=/opt/semgrep/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    STYX_WORDLISTS=/usr/share/wordlists/styx \
    TRIVY_CACHE_DIR=/opt/trivy-cache \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true \
    TRIVY_OFFLINE_SCAN=true \
    SEMGREP_SEND_METRICS=off

COPY image.json manifest.jq toolset.schema.json validate-toolset.py requirements-semgrep.txt apt-pins.txt /tmp/styx-build/
COPY etc/README /tmp/styx-build/README
COPY etc/motd /tmp/styx-build/motd

# 1. The curated package list at exactly its pinned versions. --no-install-recommends
#    and no metapackage keep the image what the manifest says it is, and the dpkg
#    loop catches a dependency that pulled a different version of a pinned package.
#    The list is apt-pins.txt, generated from image.json and checked in CI: the
#    base image has no jq yet, so nothing here may need a tool it does not carry.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends $(tr '\n' ' ' < /tmp/styx-build/apt-pins.txt); \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; \
    while read -r package want; do \
      got="$(dpkg-query -W -f='${Version}' "$package")"; \
      if [ "$got" != "$want" ]; then \
        echo "pin drift: $package is $got, pinned $want" >&2; \
        exit 1; \
      fi; \
    done < <(jq -r '[.tools[], .supporting[]] | .[] | select(.package != null) | "\(.package) \(.package_version)"' /tmp/styx-build/image.json)

# 2. semgrep has no Kali package, so it is the pinned upstream install the spec
#    names: a fully hash-locked requirements file generated from PyPI, installed
#    into its own venv so the system python is untouched. --require-hashes makes
#    pip refuse any wheel whose bytes differ from the lock.
RUN set -eux; \
    python3 -m venv /opt/semgrep; \
    /opt/semgrep/bin/pip install --no-cache-dir --require-hashes \
      -r /tmp/styx-build/requirements-semgrep.txt; \
    rm -rf /opt/semgrep/lib/python*/site-packages/pip* /root/.cache; \
    semgrep --version

# 3. Tool data, baked and checksummed (§8). A mismatch fails the build rather
#    than baking a silently different ruleset or wordlist.
RUN set -eux; \
    curl -fsSL -o /tmp/nuclei-templates.tar.gz "$(jq -r .data.nuclei_templates.url /tmp/styx-build/image.json)"; \
    echo "$(jq -r .data.nuclei_templates.sha256 /tmp/styx-build/image.json)  /tmp/nuclei-templates.tar.gz" | sha256sum -c -; \
    mkdir -p /root/nuclei-templates; \
    tar -xzf /tmp/nuclei-templates.tar.gz --strip-components=1 -C /root/nuclei-templates; \
    rm -f /tmp/nuclei-templates.tar.gz; \
    curl -fsSL -o /tmp/semgrep-rules.tar.gz "$(jq -r .data.semgrep_rules.url /tmp/styx-build/image.json)"; \
    echo "$(jq -r .data.semgrep_rules.sha256 /tmp/styx-build/image.json)  /tmp/semgrep-rules.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/semgrep-rules; \
    tar -xzf /tmp/semgrep-rules.tar.gz --strip-components=1 -C /opt/semgrep-rules; \
    rm -f /tmp/semgrep-rules.tar.gz; \
    mkdir -p /usr/share/wordlists/styx /usr/share/doc/styx; \
    while read -r name url path want; do \
      curl -fsSL -o "$path" "$url"; \
      echo "$want  $path" | sha256sum -c -; \
    done < <(jq -r '.wordlists[] | "\(.name) \(.url) \(.path) \(.sha256)"' /tmp/styx-build/image.json); \
    curl -fsSL -o "$(jq -r .data.seclists.license.path /tmp/styx-build/image.json)" "$(jq -r .data.seclists.license.url /tmp/styx-build/image.json)"; \
    echo "$(jq -r .data.seclists.license.sha256 /tmp/styx-build/image.json)  $(jq -r .data.seclists.license.path /tmp/styx-build/image.json)" | sha256sum -c -

# 4. The trivy databases, at trivy's own cache paths, so the ENV offline flags
#    are all the tool needs. They are published as OCI artefacts rather than
#    runnable images (an empty config), which BuildKit refuses as a FROM, so the
#    pinned manifest is read and its one layer fetched and verified directly:
#    the manifest digest, the layer digest, and the layer size are all pins, and
#    a fetched byte that does not match them fails the build.
RUN set -eux; \
    fetch_trivy_db() { \
      repo="$1"; manifest="$2"; layer="$3"; size="$4"; out="$5"; \
      token="$(curl -fsSL "https://ghcr.io/token?scope=repository:${repo}:pull" | jq -r .token)"; \
      got="$(curl -fsSL -H "Authorization: Bearer ${token}" \
        -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
        -H 'Accept: application/vnd.oci.image.index.v1+json' \
        "https://ghcr.io/v2/${repo}/manifests/${manifest}" | jq -r '.layers[0].digest')"; \
      if [ "$got" != "$layer" ]; then \
        echo "${repo}: the pinned manifest points at layer ${got}, not ${layer}" >&2; exit 1; \
      fi; \
      curl -fsSL -H "Authorization: Bearer ${token}" "https://ghcr.io/v2/${repo}/blobs/${layer}" -o "$out"; \
      if [ "$(stat -c %s "$out")" != "$size" ]; then \
        echo "${repo}: layer size is $(stat -c %s "$out"), pinned ${size}" >&2; exit 1; \
      fi; \
      echo "${layer#sha256:}  ${out}" | sha256sum -c -; \
    }; \
    fetch_trivy_db "$(jq -r .data.trivy_db.repo /tmp/styx-build/image.json)" \
      "$(jq -r .data.trivy_db.digest /tmp/styx-build/image.json)" \
      "$(jq -r .data.trivy_db.layer_digest /tmp/styx-build/image.json)" \
      "$(jq -r .data.trivy_db.layer_size /tmp/styx-build/image.json)" \
      /tmp/trivy-db.tar.gz; \
    mkdir -p /opt/trivy-cache/db; \
    tar -xzf /tmp/trivy-db.tar.gz -C /opt/trivy-cache/db; \
    rm -f /tmp/trivy-db.tar.gz; \
    fetch_trivy_db "$(jq -r .data.trivy_java_db.repo /tmp/styx-build/image.json)" \
      "$(jq -r .data.trivy_java_db.digest /tmp/styx-build/image.json)" \
      "$(jq -r .data.trivy_java_db.layer_digest /tmp/styx-build/image.json)" \
      "$(jq -r .data.trivy_java_db.layer_size /tmp/styx-build/image.json)" \
      /tmp/trivy-java-db.tar.gz; \
    mkdir -p /tmp/javadb /opt/trivy-cache/java-db/javadb; \
    tar -xzf /tmp/trivy-java-db.tar.gz -C /tmp/javadb; \
    java_db="$(find /tmp/javadb -name trivy-java.db | head -n 1)"; \
    if [ -z "$java_db" ]; then echo "trivy-java-db: no trivy-java.db in the layer" >&2; exit 1; fi; \
    cp -r "$(dirname "$java_db")/." /opt/trivy-cache/java-db/javadb/; \
    rm -rf /tmp/javadb /tmp/trivy-java-db.tar.gz; \
    test -s /opt/trivy-cache/db/trivy.db; \
    test -s /opt/trivy-cache/java-db/javadb/trivy-java.db

# 5. The image's declaration of itself: /etc/styx/toolset.json and
#    /etc/styx/build-info.json, both renderings of image.json, the in-image help
#    text, and a schema check so an image can never ship a manifest styx would
#    refuse to describe.
RUN set -eux; \
    mkdir -p /etc/styx; \
    cp /tmp/styx-build/README /etc/styx/README; \
    cp /tmp/styx-build/motd /etc/motd; \
    req_sha="$(sha256sum /tmp/styx-build/requirements-semgrep.txt | cut -d' ' -f1)"; \
    jq -S -f /tmp/styx-build/manifest.jq --arg toolset_sha "" --arg req_sha "$req_sha" /tmp/styx-build/image.json > /tmp/styx-build/gen.json; \
    jq -S .toolset /tmp/styx-build/gen.json > /etc/styx/toolset.json; \
    toolset_sha="$(sha256sum /etc/styx/toolset.json | cut -d' ' -f1)"; \
    jq -S -f /tmp/styx-build/manifest.jq --arg toolset_sha "$toolset_sha" --arg req_sha "$req_sha" /tmp/styx-build/image.json | jq -S .build_info > /etc/styx/build-info.json; \
    python3 /tmp/styx-build/validate-toolset.py /etc/styx/toolset.json /tmp/styx-build/toolset.schema.json; \
    chmod 0644 /etc/styx/toolset.json /etc/styx/build-info.json /etc/styx/README; \
    rm -rf /tmp/styx-build

# The session's tools run as root inside the single-purpose container because
# Docker's default capability set includes NET_RAW and SYN-style scans need it;
# no --cap-add, no docker socket, no host networking (§10).
WORKDIR /workspace
CMD ["bash"]
