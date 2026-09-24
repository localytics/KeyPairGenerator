# Variables
BINARY_NAME=keypair-generator
GO=go
GOFLAGS=-v
CMD=./cmd/keypair-generator

.PHONY: all build clean test fmt lint run generate help

all: clean fmt test build

## build: Build the keypair-generator binary into bin/
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) $(CMD)

## clean: Remove bin/, rsa_key files, output.txt, and coverage artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f rsa_key rsa_key.p8 rsa_key.pub output.txt
	rm -f coverage.out coverage.html

## test: Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -count=1 ./...

## fmt: Format and vet the module
fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## run: Build and write output.txt from existing rsa_key.p8 / rsa_key.pub
run: build
	./bin/$(BINARY_NAME)

## generate: Build and create a new unencrypted PKCS#8 key pair in the current directory
generate: build
	./bin/$(BINARY_NAME) --generate

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
