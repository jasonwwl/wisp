GO       ?= go
PKG      := github.com/jasonwwl/wisp
GOFLAGS  ?= -trimpath
LDFLAGS  ?= -s -w -buildid=
BIN      ?= bin

# Try to embed the git short SHA in development builds. Falls back to
# the runtime/debug VCS stamp when this isn't a git checkout.
COMMIT   := $(shell git rev-parse --short=7 HEAD 2>/dev/null)
ifneq ($(COMMIT),)
LDFLAGS  += -X $(PKG)/internal/version.Commit=$(COMMIT)
endif

.PHONY: all build test vet fmt tidy clean release help

all: vet test build

build:
	@mkdir -p $(BIN)
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BIN)/wisp ./cmd/wisp

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN) dist

# Cross-compile release artifacts into ./dist
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

release: $(PLATFORMS)
$(PLATFORMS):
	@mkdir -p dist
	@os=$$(echo $@ | cut -d/ -f1); arch=$$(echo $@ | cut -d/ -f2); \
	ext=$$([ "$$os" = windows ] && echo .exe || echo ""); \
	echo "  build  dist/wisp-$$os-$$arch$$ext"; \
	GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
		-o dist/wisp-$$os-$$arch$$ext ./cmd/wisp

help:
	@echo "Targets:"
	@echo "  build     compile bin/wisp for the host platform"
	@echo "  test      run unit tests with the race detector"
	@echo "  vet       run go vet"
	@echo "  fmt       run gofmt over the tree"
	@echo "  tidy      run go mod tidy"
	@echo "  release   cross-compile for all supported platforms into ./dist"
	@echo "  clean     remove bin/ and dist/"
