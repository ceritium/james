PREFIX ?= $(HOME)/.local
BIN := $(PREFIX)/bin/james

.PHONY: build install test

# The hardened runtime keeps other processes, even root, from reading the daemon's memory.
build:
	go build -o bin/james ./cmd/james
	codesign --force --sign - --options runtime --entitlements cmd/james/entitlements.plist bin/james

# Replace rather than overwrite: rewriting a signed binary in place gets it killed.
install: build
	mkdir -p $(PREFIX)/bin
	cp bin/james $(BIN).tmp
	mv -f $(BIN).tmp $(BIN)

test:
	go test ./...
