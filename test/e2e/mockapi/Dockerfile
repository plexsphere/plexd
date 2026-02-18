# syntax=docker/dockerfile:1

# Build stage — Go version must match go.mod (currently 1.24)
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Cache module downloads in a separate layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Multi-platform support — Docker sets TARGETOS/TARGETARCH automatically
# during buildx multi-platform builds
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w" \
    -o /build/mockapi \
    ./test/e2e/mockapi/cmd/mockapi

# Runtime stage — minimal distroless image (no shell, no package manager)
FROM gcr.io/distroless/static-debian12

COPY --from=builder --chown=65534:65534 /build/mockapi /usr/local/bin/mockapi

# Run as non-root (nobody)
USER 65534:65534

# Mock Central API server port
EXPOSE 8080
# Local endpoint TLS port
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/mockapi"]
CMD ["-addr", ":8080"]
