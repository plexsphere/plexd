# syntax=docker/dockerfile:1

# Build stage — Go version must match go.mod (currently 1.26)
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Cache module downloads in a separate layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build arguments for version metadata (injected via ldflags)
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# Multi-platform support — Docker sets TARGETOS/TARGETARCH automatically
# during buildx multi-platform builds. Declared without defaults: a default
# would override the per-platform values, stamping every variant amd64 (#70).
ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /build/plexd \
    ./cmd/plexd

# Fail the build when the binary does not match the requested platform.
# Compared against TARGETPLATFORM, not TARGETOS/TARGETARCH: a reintroduced
# ARG default corrupts those for the build and the check alike, while
# TARGETPLATFORM stays the platform BuildKit was asked for. The $ anchors
# keep e.g. arm from matching arm64.
ARG TARGETPLATFORM
RUN os="${TARGETPLATFORM%%/*}"; arch="${TARGETPLATFORM#*/}"; arch="${arch%%/*}"; \
    go version -m /build/plexd | grep -q "GOOS=${os}$" && \
    go version -m /build/plexd | grep -q "GOARCH=${arch}$"

# Create empty directories for the runtime stage (distroless has no shell/mkdir)
RUN mkdir -p /runtime-dirs/var/lib/plexd \
    /runtime-dirs/var/run/plexd \
    /runtime-dirs/etc/plexd \
    /runtime-dirs/var/log/plexd && \
    echo "plexd container started" > /runtime-dirs/var/log/plexd/startup.log && \
    chown -R 65534:65534 /runtime-dirs

# Runtime stage — minimal distroless image (no shell, no package manager)
FROM gcr.io/distroless/static-debian12

# Data directories required at runtime
COPY --from=builder /runtime-dirs/ /

COPY --from=builder --chown=65534:65534 /build/plexd /usr/local/bin/plexd

# Run as non-root (nobody)
USER 65534:65534

# Node API (TCP, optional) and health checks (TCP), WireGuard mesh (UDP)
EXPOSE 9100 9101 51820/udp

ENTRYPOINT ["/usr/local/bin/plexd"]
