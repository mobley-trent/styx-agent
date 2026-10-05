# styx-agent developer tasks. `make check` runs the same gate as CI.

VERSION ?=

# When VERSION is set (e.g. `make build VERSION=v0.1.0`), stamp the binary
# the same way goreleaser does; otherwise plain go build keeps VCS stamping.
BUILD_LDFLAGS := $(if $(VERSION),-ldflags "-X main.versionOverride=$(VERSION)",)

GOLANGCI_LINT_VERSION := v2.14.0

.DEFAULT_GOAL := help
.PHONY: help build vet lint test fmt clean check release release-dry-run

help: ## show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

build: ## build the styx binary
	go build $(BUILD_LDFLAGS) -o styx ./cmd/styx

vet: ## go vet the module
	go vet ./...

lint: ## golangci-lint (same config as CI)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found; install with:"; \
		echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
		exit 1; }
	golangci-lint run ./...

test: ## run tests with the race detector
	go test -race ./...

fmt: ## gofmt the tree in place
	gofmt -l -w .

clean: ## remove build artifacts
	rm -f styx

# One command for the full CI gate, in CI's order, always sequential.
.NOTPARALLEL: check
check: build vet lint test ## run the full CI gate locally

# Cut and publish a release from main: promote CHANGELOG.md, run the gate, tag,
# and push (the tag triggers the release workflow). See RELEASING.md.
release: ## cut a release: make release VERSION=vX.Y.Z (tags and pushes)
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=vX.Y.Z"; exit 1; }
	scripts/release.sh "$(VERSION)"

release-dry-run: ## preview a release without tagging: make release-dry-run VERSION=vX.Y.Z
	@test -n "$(VERSION)" || { echo "usage: make release-dry-run VERSION=vX.Y.Z"; exit 1; }
	scripts/release.sh --dry-run "$(VERSION)"
