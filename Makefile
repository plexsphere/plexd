.PHONY: build test test-e2e lint vet

build:
	go build ./...

test:
	go test -race -count=1 ./...

test-e2e:
	go test -race -count=1 -run Integration ./...

lint: vet
	golangci-lint run

vet:
	go vet ./...
