# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY internal/oms/protocol/ internal/oms/protocol/
COPY internal/oms/kd6adapter/ internal/oms/kd6adapter/
COPY cmd/orka-oms-kd6-adapter/ cmd/orka-oms-kd6-adapter/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" \
    -o /out/orka-oms-kd6-adapter ./cmd/orka-oms-kd6-adapter && \
    mkdir -p /out/data

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/orka-oms-kd6-adapter /orka-oms-kd6-adapter
COPY --from=builder --chown=65532:65532 /out/data /data

USER 65532:65532
EXPOSE 8091
VOLUME ["/data"]

ENTRYPOINT ["/orka-oms-kd6-adapter"]
