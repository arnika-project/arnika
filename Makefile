# Define the name of the application and its version
NAME := arnika
VERSION := $(shell git describe --long --always)

# Define the Go compiler and other tools
GO = go

# Build flags
GO_BUILD_VARS := CGO_ENABLED=0
BUILD_FLAGS = -trimpath -ldflags "-w -s -extldflags=-Wl,-Bsymbolic -X 'main.Version=$(VERSION)' -X 'main.APPName=$(NAME)'"
BINARY_NAME ?= arnika
BUILD_DIR ?= build

# Default target: build the binary
default: $(BUILD_DIR)/$(BINARY_NAME)

# Build rule: create a new executable
build:
	@echo "Building $(BINARY_NAME)"
	$(GO_BUILD_VARS) $(GO) build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Clean rule: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)/*

.PHONY: default build clean
