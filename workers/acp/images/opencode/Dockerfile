# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The tag documents the human-readable version; the manifest-list digest and
# checksum-verified upstream archives make every supported platform immutable.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS upstream-artifacts
ARG TARGETARCH
COPY workers/acp/images/artifact-tool.go /tmp/artifact-tool.go
COPY workers/acp/images/opencode/AGENTS.md /tmp/opencode-AGENTS.md
COPY workers/acp/images/opencode/NOTICE.md /tmp/orka-NOTICE.md
ADD --checksum=sha256:33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c \
    https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz /artifacts/ripgrep-linux-x64.tgz
ADD --checksum=sha256:800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915 \
    https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/ripgrep-15.2.0-aarch64-unknown-linux-musl.tar.gz /artifacts/ripgrep-linux-arm64.tgz
RUN go build -buildvcs=false -trimpath -ldflags='-s -w' -o /usr/local/bin/artifact-tool /tmp/artifact-tool.go
RUN set -eu; \
    mkdir -p /artifacts /src; \
    artifact-tool download \
      "https://codeload.github.com/anomalyco/opencode/tar.gz/4da7bb44c84e013fa53e9c5d02ac753d1435c81a" \
      "bbc3363c6886c63865a60b75d456fff3fbe6b87d8a86f44b2439900695b35de3" \
      /artifacts/opencode-source.tgz 100663296; \
    case "$TARGETARCH" in \
      amd64) \
        native_url="https://registry.npmjs.org/opencode-linux-x64-baseline/-/opencode-linux-x64-baseline-1.18.9.tgz"; \
        native_sha="59bf22db1f20c6c9836c926800a8e6416228330c2b518ade3d431d315cd76366" ;; \
      arm64) \
        native_url="https://registry.npmjs.org/opencode-linux-arm64/-/opencode-linux-arm64-1.18.9.tgz"; \
        native_sha="4846a7e470797950f209126442a291cc06574fd44ddbb96c89d730017f60aae7" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    artifact-tool download \
      "$native_url" "$native_sha" /artifacts/opencode-native.tgz 100663296; \
    tar -xzf /artifacts/opencode-source.tgz -C /src --strip-components=1; \
    grep -Eq '"name":[[:space:]]*"opencode"' /src/packages/opencode/package.json; \
    grep -Eq '"version":[[:space:]]*"1\.18\.9"' /src/packages/opencode/package.json; \
    printf '%s  %s\n' '625f0f619133f89bbbb2abe37369613dfa1885eba1e50d02170deb62bb42cb6b' /src/LICENSE | sha256sum -c -; \
    printf '%s  %s\n' 'b8e691e210a9502c9689ba20705806dfb1b5b10b5ca1062f73f9a85b1043a812' /tmp/opencode-AGENTS.md | sha256sum -c -; \
    printf '%s  %s\n' '93167c1d7505d3e38efce8bf019c2af4e10ef56529465b87c34e4b3401508a98' /tmp/orka-NOTICE.md | sha256sum -c -; \
    cp /src/LICENSE /artifacts/opencode-LICENSE; \
    cp /src/README.md /artifacts/opencode-README.md; \
    cp /tmp/opencode-AGENTS.md /artifacts/opencode-AGENTS.md; \
    cp /tmp/orka-NOTICE.md /artifacts/orka-NOTICE.md; \
    artifact-tool download \
      "https://raw.githubusercontent.com/orka-agents/orka/d03acb995b6014a6e855181c50b922b65ea8e7ff/LICENSE" \
      "7df20dcdf9197e9945c14858d41c60f11b52b93e5b69e2b63416b874d598d322" \
      /artifacts/orka-LICENSE 65536

FROM --platform=$TARGETPLATFORM docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS opencode-layout
ARG TARGETARCH
COPY --from=upstream-artifacts /artifacts/opencode-native.tgz /tmp/opencode-native.tgz
COPY --from=upstream-artifacts /artifacts/ripgrep-linux-x64.tgz /tmp/ripgrep-linux-x64.tgz
COPY --from=upstream-artifacts /artifacts/ripgrep-linux-arm64.tgz /tmp/ripgrep-linux-arm64.tgz
RUN set -eu; \
    mkdir -p /tmp/native /tmp/ripgrep /opt/opencode/bin /opt/ripgrep/bin /opt/ripgrep/licenses; \
    tar -xzf /tmp/opencode-native.tgz -C /tmp/native; \
    case "$TARGETARCH" in \
      amd64) \
        package_name=opencode-linux-x64-baseline; \
        binary_sha=7c4d91c84d2bfdeabb59257e3490c5e5acb08f2aacb3e42f3ddc296a1c3f1aca; \
        ripgrep_archive=/tmp/ripgrep-linux-x64.tgz; \
        ripgrep_target=x86_64-unknown-linux-musl; \
        ripgrep_sha=e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849 ;; \
      arm64) \
        package_name=opencode-linux-arm64; \
        binary_sha=ae8a9b7c591d3c763463f16bfb5f45230c4c741f039e8967218662836449ecdf; \
        ripgrep_archive=/tmp/ripgrep-linux-arm64.tgz; \
        ripgrep_target=aarch64-unknown-linux-musl; \
        ripgrep_sha=c14cdb389f34e504d69e386cfc67d5c5d9a730a990de03ca6910b2a15e30386a ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    grep -Eq '"name":[[:space:]]*"'"$package_name"'"' /tmp/native/package/package.json; \
    grep -Eq '"version":[[:space:]]*"1\.18\.9"' /tmp/native/package/package.json; \
    test -x /tmp/native/package/bin/opencode; \
    printf '%s  %s\n' "$binary_sha" /tmp/native/package/bin/opencode | sha256sum -c -; \
    install -m 0755 /tmp/native/package/bin/opencode /opt/opencode/bin/opencode; \
    test "$(/opt/opencode/bin/opencode --version)" = "1.18.9"; \
    tar -xzf "$ripgrep_archive" -C /tmp/ripgrep; \
    ripgrep_root="/tmp/ripgrep/ripgrep-15.2.0-$ripgrep_target"; \
    test -x "$ripgrep_root/rg"; \
    printf '%s  %s\n' "$ripgrep_sha" "$ripgrep_root/rg" | sha256sum -c -; \
    install -m 0755 "$ripgrep_root/rg" /opt/ripgrep/bin/rg; \
    cp "$ripgrep_root/LICENSE-MIT" "$ripgrep_root/UNLICENSE" /opt/ripgrep/licenses/; \
    /opt/ripgrep/bin/rg --version | grep -Eq '^ripgrep 15\.2\.0'

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS supervisor-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download
COPY . .
RUN set -eu; \
    grep -Eq '^[[:space:]]*OpenCodeVersion[[:space:]]*= "1\.18\.9"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeSourceCommit[[:space:]]*= "4da7bb44c84e013fa53e9c5d02ac753d1435c81a"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeSourceTarSHA256[[:space:]]*= "bbc3363c6886c63865a60b75d456fff3fbe6b87d8a86f44b2439900695b35de3"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeLinuxX64BaselineTarSHA256[[:space:]]*= "59bf22db1f20c6c9836c926800a8e6416228330c2b518ade3d431d315cd76366"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeLinuxARM64TarSHA256[[:space:]]*= "4846a7e470797950f209126442a291cc06574fd44ddbb96c89d730017f60aae7"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeLinuxX64BinarySHA256[[:space:]]*= "7c4d91c84d2bfdeabb59257e3490c5e5acb08f2aacb3e42f3ddc296a1c3f1aca"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeLinuxARM64BinarySHA256[[:space:]]*= "ae8a9b7c591d3c763463f16bfb5f45230c4c741f039e8967218662836449ecdf"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeRipgrepVersion[[:space:]]*= "15\.2\.0"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeRipgrepLinuxX64TarSHA256[[:space:]]*= "33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeRipgrepLinuxARM64TarSHA256[[:space:]]*= "800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeRipgrepLinuxX64BinarySHA256[[:space:]]*= "e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeRipgrepLinuxARM64BinarySHA256[[:space:]]*= "c14cdb389f34e504d69e386cfc67d5c5d9a730a990de03ca6910b2a15e30386a"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeRootInstructionSHA256[[:space:]]*= "b8e691e210a9502c9689ba20705806dfb1b5b10b5ca1062f73f9a85b1043a812"$' internal/acp/pins.go; \
    grep -Eq '^[[:space:]]*OpenCodeImageNoticeSHA256[[:space:]]*= "93167c1d7505d3e38efce8bf019c2af4e10ef56529465b87c34e4b3401508a98"$' internal/acp/pins.go; \
    test "$TARGETOS" = linux; \
    case "$TARGETARCH" in amd64|arm64) ;; *) exit 1 ;; esac; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -buildvcs=false -trimpath -ldflags='-s -w' \
      -o /out/orka-acp-runtime ./cmd/orka-acp-runtime; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -buildvcs=false -trimpath -ldflags='-s -w' \
      -o /out/orka-acp-exec-helper ./cmd/orka-acp-exec-helper

FROM --platform=$TARGETPLATFORM docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
LABEL org.opencontainers.image.title="Orka ACP OpenCode runtime" \
      org.opencontainers.image.description="Orka harness v2 ACP supervisor with native OpenCode ACP 1.18.9" \
      org.opencontainers.image.source="https://github.com/orka-agents/orka" \
      org.opencontainers.image.licenses="MIT AND (MIT OR Unlicense)" \
      io.orka.acp.provider="opencode" \
      io.orka.acp.adapter.version="1.18.9" \
      io.orka.acp.adapter.revision="4da7bb44c84e013fa53e9c5d02ac753d1435c81a" \
      io.orka.acp.adapter.source.digest="sha256:bbc3363c6886c63865a60b75d456fff3fbe6b87d8a86f44b2439900695b35de3" \
      io.orka.acp.adapter.digest.amd64="sha256:59bf22db1f20c6c9836c926800a8e6416228330c2b518ade3d431d315cd76366" \
      io.orka.acp.adapter.digest.arm64="sha256:4846a7e470797950f209126442a291cc06574fd44ddbb96c89d730017f60aae7" \
      io.orka.acp.adapter.binary.digest.amd64="sha256:7c4d91c84d2bfdeabb59257e3490c5e5acb08f2aacb3e42f3ddc296a1c3f1aca" \
      io.orka.acp.adapter.binary.digest.arm64="sha256:ae8a9b7c591d3c763463f16bfb5f45230c4c741f039e8967218662836449ecdf" \
      io.orka.acp.ripgrep.version="15.2.0" \
      io.orka.acp.ripgrep.archive.digest.amd64="sha256:33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c" \
      io.orka.acp.ripgrep.archive.digest.arm64="sha256:800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915" \
      io.orka.acp.ripgrep.binary.digest.amd64="sha256:e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849" \
      io.orka.acp.ripgrep.binary.digest.arm64="sha256:c14cdb389f34e504d69e386cfc67d5c5d9a730a990de03ca6910b2a15e30386a" \
      io.orka.acp.root-instruction.digest="sha256:b8e691e210a9502c9689ba20705806dfb1b5b10b5ca1062f73f9a85b1043a812" \
      io.orka.notice.digest="sha256:93167c1d7505d3e38efce8bf019c2af4e10ef56529465b87c34e4b3401508a98"
ENV HOME=/root \
    ORKA_ACP_PROVIDER=opencode \
    PATH=/usr/local/bin:/usr/bin:/bin
RUN set -eu; \
    mkdir -p /sessions /opt/opencode /usr/share/licenses/orka /usr/share/licenses/opencode /usr/share/licenses/ripgrep; \
    chmod 0711 /sessions
COPY --from=supervisor-builder /out/orka-acp-runtime /usr/local/bin/orka-acp-runtime
COPY --from=supervisor-builder /out/orka-acp-exec-helper /usr/local/bin/orka-acp-exec-helper
COPY --from=opencode-layout /opt/opencode/bin/opencode /opt/opencode/bin/opencode
COPY --from=opencode-layout /opt/ripgrep/bin/rg /usr/local/bin/rg
COPY --from=opencode-layout /opt/ripgrep/licenses/LICENSE-MIT /opt/ripgrep/licenses/UNLICENSE /usr/share/licenses/ripgrep/
COPY --from=upstream-artifacts /artifacts/opencode-AGENTS.md /opt/opencode/AGENTS.md
COPY --from=upstream-artifacts /artifacts/opencode-README.md /opt/opencode/README.md
COPY --from=upstream-artifacts /artifacts/opencode-LICENSE /usr/share/licenses/opencode/LICENSE
COPY --from=upstream-artifacts /artifacts/orka-LICENSE /usr/share/licenses/orka/LICENSE
COPY --from=upstream-artifacts /artifacts/orka-NOTICE.md /usr/share/licenses/orka/NOTICE.md
WORKDIR /
# The supervisor must start as root to assign each child a unique UID/GID and
# prove process cleanup. Kubernetes drops all capabilities and adds back only
# the explicit identity/process-management set.
# trivy:ignore:DS-0002
USER 0:0
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/orka-acp-runtime"]
