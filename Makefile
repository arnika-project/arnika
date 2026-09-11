# Define the name of the application and its version
NAME := arnika
VERSION := $(shell git describe --tags --always)

# Define the Go compiler and other tools
GO = go

# Build flags
GO_BUILD_VARS := CGO_ENABLED=0 GOEXPERIMENT=runtimesecret
BUILD_FLAGS = -trimpath -ldflags "-w -s -extldflags=-Wl,-Bsymbolic -X 'main.Version=$(VERSION)' -X 'main.APPName=$(NAME)'"
BINARY_NAME ?= arnika
BUILD_DIR ?= build

# Optional Go build tags selecting one backend per port (see KEYCONTROL.md).
# One tag family per port, defaults apply when the family is not named:
#   key writer:  wireguard_netlink [default] | wireguard_netlink_netns | wireguard_mikrotik
#   QKD reader:  qkd_kms [default] | qkd_none  (qkd_none drops net/http and crypto/tls, -40% size)
# The PQC reader has one backend and no tag; PQC_ENABLED switches it at runtime.
# Usage: make build BUILD_TAGS="wireguard_mikrotik qkd_none"
BUILD_TAGS ?=
TAGS_FLAG := $(if $(BUILD_TAGS),-tags "$(BUILD_TAGS)",)

# Default target: build the binary
default: build

# Build rule: create a new executable
build:
	@echo "Building $(BINARY_NAME)$(if $(BUILD_TAGS), (tags: $(BUILD_TAGS)),)"
	$(GO_BUILD_VARS) $(GO) build $(BUILD_FLAGS) $(TAGS_FLAG) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Convenience targets for each key writer backend
build-netlink:
	$(MAKE) build BUILD_TAGS=wireguard_netlink

build-mikrotik:
	$(MAKE) build BUILD_TAGS=wireguard_mikrotik

# PQC-only binary: no KMS client, no net/http, no crypto/tls
build-pqc-only:
	$(MAKE) build BUILD_TAGS=qkd_none

# End to end lab: two Arnika nodes and the KMS simulator in containers
E2E_FLAGS ?=
test-e2e:
	$(GO) test -C ci/e2e -v -count=1 -timeout 15m $(E2E_FLAGS) ./...

# Clean rule: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)/*

.PHONY: default build build-netlink build-mikrotik build-pqc-only test-e2e clean
