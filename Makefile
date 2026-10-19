.PHONY: build run test check test-race audit e2e-docker bench bench-docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/relay ./cmd/relay

run: build
	./bin/relay

test: check test-race

check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go mod tidy -diff
	go vet ./...
	go vet -tags dockere2e ./e2e/docker
	go fix -diff ./...
	go fix -diff -tags dockere2e ./e2e/docker

test-race:
	go test -race -count=1 -shuffle=on ./...

audit:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./cmd/relay

e2e-docker:
	./e2e/docker/run.sh

bench: build
	go run ./e2e/bench -spawn -relay-bin bin/relay

bench-docker:
	./e2e/docker/bench.sh
