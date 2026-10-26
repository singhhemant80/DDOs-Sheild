# Build all deployable artifacts. Run on a build machine (Go 1.22+, Node 20.19+), then copy the
# repository to the Shield server and run deploy/scripts/install.sh, which does not need Go or Node.

GO       ?= go
NPM      ?= npm
BIN      := collector/bin

.PHONY: all collector frontend test test-go test-api clean

all: collector frontend

collector:
	cd collector && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/ ./cmd/...

frontend:
	cd frontend && $(NPM) ci && $(NPM) run build

test: test-go test-api

test-go:
	cd collector && $(GO) vet ./... && $(GO) test ./...

# Needs SHIELD_TEST_DATABASE_URL (and optionally SHIELD_TEST_REDIS_URL / SHIELD_TEST_CLICKHOUSE_URL).
test-api:
	cd backend && python3 -m pytest -q

clean:
	rm -rf $(BIN) frontend/dist
