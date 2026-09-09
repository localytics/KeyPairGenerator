# Variables
BINARY_NAME=keypair-generator
GO=go
GOFLAGS=-v

.PHONY: all build clean test fmt run generate help

all: clean fmt test build

## build: Build the keypair-generator binary into bin/
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) .

## clean: Remove bin/, rsa_key files, and coverage artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f rsa_key rsa_key.p8 rsa_key.pub
	rm -f coverage.out coverage.html

## test: Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -count=1 ./...

## fmt: Format and vet the package
fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

## run: Build and print values from existing rsa_key.p8 / rsa_key.pub
run: build
	./bin/$(BINARY_NAME)

## generate: Build and create a new unencrypted PKCS#8 key pair in the current directory
generate: build
	./bin/$(BINARY_NAME) -generate

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
