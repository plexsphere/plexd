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
# during buildx multi-platform builds
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /build/plexd \
    ./cmd/plexd

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
