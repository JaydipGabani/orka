# Development controller image: source preparation requires Git and prlimit,
# which are deliberately absent from the normal distroless controller image.
FROM alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache git util-linux
COPY manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
