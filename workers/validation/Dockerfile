# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM --platform=$TARGETPLATFORM docker.io/library/golang:1.26.5-trixie@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
ENV TMPDIR=/build/work GOTOOLCHAIN=go1.27.0
RUN mkdir -p /build/work /artifacts
COPY go.mod go.sum ./
COPY internal/patchverification/ ./internal/patchverification/
COPY workers/validation/ ./workers/validation/
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    test "$TARGETOS" = linux; \
    case "$TARGETARCH" in amd64|arm64) ;; *) exit 1 ;; esac; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -buildvcs=false -trimpath -ldflags='-s -w' \
      -o /artifacts/orka-validation-worker ./workers/validation; \
    cc -std=c11 -O2 -Wall -Wextra -Werror -static \
      -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
      -o /artifacts/orka-validation-guard workers/validation/guard/guard.c; \
    chmod 0555 /artifacts/orka-validation-worker /artifacts/orka-validation-guard

FROM docker.io/library/alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
LABEL org.opencontainers.image.title="Orka supervised validation worker" \
      org.opencontainers.image.description="Static observer and per-process seccomp guard for per-check Kubernetes validation" \
      org.opencontainers.image.source="https://github.com/orka-agents/orka" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /artifacts/ /artifacts/
USER 0:0
ENTRYPOINT ["/bin/cp", "/artifacts/orka-validation-worker", "/artifacts/orka-validation-guard", "/runner/"]
