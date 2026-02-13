# Suggested Commands

## Build & Verify
- `go build ./...` - Build entire project
- `go build ./internal/packaging/` - Build specific package
- `go vet ./...` - Vet entire project
- `go vet ./internal/packaging/` - Vet specific package
- `go test ./...` - Run all tests
- `go test ./internal/packaging/` - Run tests in specific package
- `go test -race ./...` - Run tests with race detector

## Formatting
- `gofmt -w .` - Format all Go files

## Other
- `go mod tidy` - Tidy module dependencies
