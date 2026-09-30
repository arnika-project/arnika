NAME := arnika
VERSION := $(shell git describe --tags --always)

GO = go
GOLANGCI_LINT ?= golangci-lint

GO_BUILD_VARS := CGO_ENABLED=0 GOEXPERIMENT=runtimesecret
BUILD_FLAGS = -trimpath -ldflags "-w -s -extldflags=-Wl,-Bsymbolic -X 'main.Version=$(VERSION)' -X 'main.APPName=$(NAME)'"
BINARY_NAME ?= arnika
BUILD_DIR ?= build

# Backend tags per port: see KEYCONTROL.md, e.g. BUILD_TAGS="wireguard_mikrotik qkd_none"
BUILD_TAGS ?=
TAGS_FLAG := $(if $(BUILD_TAGS),-tags "$(BUILD_TAGS)",)

default: build

build:
	@echo "Building $(BINARY_NAME)$(if $(BUILD_TAGS), (tags: $(BUILD_TAGS)),)"
	$(GO_BUILD_VARS) $(GO) build $(BUILD_FLAGS) $(TAGS_FLAG) -o $(BUILD_DIR)/$(BINARY_NAME) .

build-netlink:
	$(MAKE) build BUILD_TAGS=wireguard_netlink

build-mikrotik:
	$(MAKE) build BUILD_TAGS=wireguard_mikrotik

build-pqc-only:
	$(MAKE) build BUILD_TAGS=qkd_none

lint:
	$(GOLANGCI_LINT) run ./...

# Include build-tagged files and nested modules.
fmt:
	find . -type f -name '*.go' -not -path './.git/*' -exec gofmt -w {} +

E2E_FLAGS ?=
test-e2e:
	$(GO) test -C ci/e2e -v -count=1 -timeout 15m $(E2E_FLAGS) ./...

clean:
	rm -rf $(BUILD_DIR)/*

.PHONY: default build build-netlink build-mikrotik build-pqc-only lint fmt test-e2e clean
