# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS builder
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /workspace
COPY go.mod go.sum ./
COPY cmd/orka-remediation-observer/ ./cmd/orka-remediation-observer/
RUN test "$TARGETOS" = linux && mkdir -p bin/build \
    && TMPDIR=/workspace/bin/build CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
       GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
       -o bin/orka-remediation-observer ./cmd/orka-remediation-observer

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=builder /workspace/bin/orka-remediation-observer /orka-remediation-observer
USER 65532:65532
EXPOSE 8080 8443 6379
ENTRYPOINT ["/orka-remediation-observer"]
