# eimer: S3 estate compliance audit. `just` lists recipes.

version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
ldflags := "-s -w -X main.version=" + version

default:
    @just --list

# Build ./bin/eimer for this machine
build:
    go build -trimpath -ldflags "{{ldflags}}" -o bin/eimer ./cmd/eimer

# Cross-compile linux/amd64 (for a bastion on the storage LAN) into ./bin/eimer-linux-amd64
build-linux:
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "{{ldflags}}" -o bin/eimer-linux-amd64 ./cmd/eimer

# Run unit tests with the race detector
test:
    go test -race -cover ./...

# gofmt + go vet + golangci-lint
lint:
    test -z "$(gofmt -l .)" || (gofmt -l . && echo 'run: just fmt' && exit 1)
    go vet ./...
    golangci-lint run ./...

# Format all Go files in place
fmt:
    gofmt -w .

# Everything CI runs
check: lint test build

# Keep go.mod and go.sum tidy
tidy:
    go mod tidy

# Audit a throwaway local MinIO with one locked and one plain bucket
smoke: build
    ./scripts/smoke-local.sh

# Audit a store from a bastion that can reach it: copy the binary over, run it with the keys
# on stdin from a local dotenv file, fetch the report into ./evidence, remove everything again.
smoke-remote host endpoint envfile=".env": build-linux
    scp bin/eimer-linux-amd64 {{host}}:/tmp/eimer
    ssh -o ServerAliveInterval=30 {{host}} '/tmp/eimer audit --env-file /dev/stdin --endpoint {{endpoint}} -v --out /tmp/eimer-report.json' < {{envfile}} || true
    mkdir -p evidence
    scp '{{host}}:/tmp/eimer-report.json*' evidence/
    ssh {{host}} 'rm -f /tmp/eimer /tmp/eimer-report.json /tmp/eimer-report.json.sha256'
    @echo "report in evidence/, nothing left on {{host}}"

# Validate the goreleaser config and build a local snapshot into ./dist (no publish)
release-snapshot:
    goreleaser check
    goreleaser release --snapshot --clean --skip=publish

# Remove build output
clean:
    rm -rf bin dist
