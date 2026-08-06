# syntax=docker/dockerfile:1.7.1@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Build the stateless coexistence admission service.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .

RUN mkdir -p internal/uiembed/dist && [ -f internal/uiembed/dist/index.html ] || echo '<!doctype html>' > internal/uiembed/dist/index.html
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -o orka-admission ./cmd/orka-admission

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/orka-admission .
USER 65532:65532

ENTRYPOINT ["/orka-admission"]
