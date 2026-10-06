# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /workspace
COPY go.mod go.sum ./
RUN mkdir -p bin/build && TMPDIR=/workspace/bin/build go mod download
COPY internal/remediation/buildjob/ ./internal/remediation/buildjob/
COPY internal/remediation/provenance/ ./internal/remediation/provenance/
COPY cmd/orka-remediation-build-worker/ ./cmd/orka-remediation-build-worker/
RUN test "$TARGETOS" = linux && TMPDIR=/workspace/bin/build CGO_ENABLED=0 GOTOOLCHAIN=local \
    GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
    -o bin/orka-remediation-build-worker ./cmd/orka-remediation-build-worker

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS buildctl
ARG TARGETARCH
WORKDIR /src
# The distribution client is dynamically linked; build a checksum-bound static
# client so the trusted worker can use the minimal, shell-free runtime below.
RUN GOTOOLCHAIN=local go mod download -json github.com/moby/buildkit@v0.31.1 > /tmp/buildctl-module.json \
    && grep -Fq '"Sum": "h1:j3p55abBl4kiXXPZgYX+6zWgB2aefqHXoPown12fIzU="' /tmp/buildctl-module.json
RUN cd /go/pkg/mod/github.com/moby/buildkit@v0.31.1 \
    && CGO_ENABLED=0 GOTOOLCHAIN=local GOOS=linux GOARCH=${TARGETARCH} \
       go build -mod=readonly -trimpath -buildvcs=false \
       -ldflags="-s -w -X github.com/moby/buildkit/version.Version=v0.31.1 -X github.com/moby/buildkit/version.Revision=673b7e0196de0cac83308274b88aaed97a91af74" \
       -o /out/buildctl ./cmd/buildctl

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=builder /workspace/bin/orka-remediation-build-worker /orka-remediation-build-worker
COPY --from=buildctl /out/buildctl /usr/bin/buildctl
COPY --from=buildctl /go/pkg/mod/github.com/moby/buildkit@v0.31.1/LICENSE /usr/share/licenses/buildkit/LICENSE
USER 65532:65532
ENTRYPOINT ["/orka-remediation-build-worker"]
