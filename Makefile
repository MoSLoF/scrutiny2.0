## Scrutiny v2 — Build System
## MoSLoF / HoneyBadger Vanguard

BINARY       := scrutiny
MODULE       := github.com/MoSLoF/scrutiny2.0
CMD          := ./cmd/scrutiny
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v2.0.0-dev")
LDFLAGS      := -ldflags "-s -w -X main.Version=$(VERSION)"
BUILD_DIR    := ./dist

BPF_SRC      := internal/sensor/ebpf/bpf/syscall_trace.c
BPF_OBJ      := internal/sensor/ebpf/bpf/syscall_trace.o
CLANG        := clang
BPF_CFLAGS   := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
                -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

## ─── eBPF Compilation ──────────────────────────────────────────────────────────
## The compiled .o is a build artifact — never commit it, never hand-copy it.
## go:embed requires it to exist at `go build` time, so every Go target below
## depends on this rule. Regenerates automatically when the .c source changes.

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

.PHONY: bpf
bpf: $(BPF_OBJ)                     ## Compile the eBPF C source to bytecode

## ─── Primary Targets ──────────────────────────────────────────────────────────

.DEFAULT_GOAL := build

.PHONY: build
build: bpf                          ## Build for current platform
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

.PHONY: all
all: linux windows arm64 arm        ## Build all release targets

.PHONY: linux
linux: bpf                          ## Linux AMD64 (server / desktop)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(CMD)

.PHONY: windows
windows: bpf                        ## Windows AMD64 (native + WSL host)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)

.PHONY: arm64
arm64: bpf                          ## Linux ARM64 (Pi 5, Pi Zero 2 W)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64 $(CMD)

.PHONY: arm
arm: bpf                            ## Linux ARMv7 (older Pi nodes)
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-armv7 $(CMD)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

all: $(BUILD_DIR)

## ─── Dev / Test ───────────────────────────────────────────────────────────────

.PHONY: run
run:                                ## Run syscheck on current machine
	go run $(CMD) syscheck

.PHONY: test
test:                               ## Run all tests
	go test ./... -v -race

.PHONY: vet
vet:                                ## Run go vet
	go vet ./...

.PHONY: lint
lint:                               ## Run staticcheck (install if needed)
	@which staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

.PHONY: check
check: vet lint test                ## Full pre-commit check

## ─── Dependency Management ────────────────────────────────────────────────────

.PHONY: deps
deps:                               ## Download and tidy dependencies
	go mod download
	go mod tidy

.PHONY: deps-upgrade
deps-upgrade:                       ## Upgrade all dependencies
	go get -u ./...
	go mod tidy

## ─── Scrutiny-specific targets ────────────────────────────────────────────────

.PHONY: syscheck
syscheck: build                     ## Build and run capability check
	./$(BINARY) syscheck

.PHONY: syscheck-json
syscheck-json: build                ## syscheck with JSON output
	./$(BINARY) syscheck --json

## ─── Compatibility targets (mirrors original Scrutiny Makefile) ───────────────

.PHONY: clean
clean:                              ## Remove build artifacts
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-arm64 $(BINARY)-armv7
	rm -f $(BPF_OBJ)
	rm -rf $(BUILD_DIR)
	rm -f *.log baselines/*.json observations/*.json

## ─── Help ─────────────────────────────────────────────────────────────────────

.PHONY: help
help:                               ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
