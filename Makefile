.PHONY: build test test-e2e test-e2e-docker lint vet docker-build

build:
	go build ./...

test:
	go test -race -count=1 ./...

test-e2e:
	go test -race -count=1 -run Integration ./...

test-e2e-docker:
	bash test/e2e/docker/test.sh

lint: vet
	golangci-lint run

vet:
	go vet ./...

docker-build:
	docker build -f deploy/docker/Dockerfile \
		--build-arg VERSION=$(shell git describe --tags --always 2>/dev/null || echo dev) \
		--build-arg COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo none) \
		--build-arg DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t ghcr.io/plexsphere/plexd:dev .
