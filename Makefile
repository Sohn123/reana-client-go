# This file is part of REANA.
# Copyright (C) 2022, 2025, 2026 CERN.
#
# REANA is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

# Allocate a TTY only when stdin is one, so the target also runs unattended
# (CI, scripts); `docker run -t` fails outright without a terminal.
DOCKER_TTY := $(shell [ -t 0 ] && echo -t)

# Keep this pin in step with the committed client/ tree: the generator's output
# changes between releases (v0.32.3 emits `interface{}` and `err != io.EOF`,
# v0.33.2+ drops the per-file header, v0.36+ splits the go-openapi/swag import),
# so regenerating with the wrong one rewrites every file for no reason.
SWAGGER := docker run --rm -i $(DOCKER_TTY) --user $(shell id -u):$(shell id -g) \
	-e HOME=/tmp -e GOPATH=/tmp/go \
	-e PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
	-v $(shell go env GOROOT):/usr/local/go:ro -v $(HOME):$(HOME) \
	-w $(shell pwd) --pull always quay.io/goswagger/swagger:v0.33.1

all: help

audit: # Run quality control checks.
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go mod verify
	go vet ./...
	staticcheck ./cmd/... ./pkg/...
	govulncheck ./...

build: # Build reana-client-go executable.
	go build

clean: # Clean build.
	rm -f reana-client-go

help: # Print usage help information.
	@echo "Available commands:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?# .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?# "}; {printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2}'

release: # Prepare standalone reana-client-go-* executables for release.
	version=$(shell go run . version) && \
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o reana-client-go-$$version-darwin-amd64 && \
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o reana-client-go-$$version-darwin-arm64 && \
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o reana-client-go-$$version-linux-amd64 && \
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o reana-client-go-$$version-linux-arm64

swagger-generate-client: # Generate OpenAPI client.
	rm -f client/api_client.go client/operations/*.go models/*.go
	$(SWAGGER) generate client -f "../reana-server/docs/openapi.json" -A api

swagger-validate-specs: # Validate OpenAPI specification.
	$(SWAGGER) validate "../reana-server/docs/openapi.json"

test: # Run test suite.
	go test -coverprofile coverage.txt ./client ./cmd/... ./pkg/...

tidy: # Format code and tidy go.mod.
	go install github.com/segmentio/golines@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go fmt ./...
	goimports -w .
	golines -w -m 80 -t 4 .
	go mod tidy

update: # Update go module dependencies.
	go get -u
	go mod tidy

.PHONY: all audit build clean help release swagger-generate-client swagger-validate-specs test tidy update
