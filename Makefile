BINARY_NAME := $(shell basename "$(PWD)")
VERSION := $(shell git describe --tags --always)

GOBASE := $(shell pwd)
GOPATH := $(GOBASE)/vendor:$(GOBASE)
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard cmd/*.go)

LDFLAGS :=-ldflags "-w -X=github.com/pjbgf/zaz/cmd.gitcommit=$(VERSION) -extldflags -static"

.PHONY: all build clean test test-all verify export-coverage download-tools

all: build


run: 
	@-$(GOBIN)/$(BINARY_NAME)


clean:
	@-rm $(GOBIN)/$(BINARY_NAME) 2> /dev/null
	@-$(MAKE) go-clean


build: go-get go-build

go-get:
	@echo "  >  Checking if there is any missing dependencies..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go get $(get)

go-build:
	@echo "  >  Building binary..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -mod=readonly -a $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) $(GOFILES)

go-generate:
	@echo "  >  Generating dependency files..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go generate $(generate)

go-clean:
	@echo "  >  Cleaning build cache"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go clean


test: go-test
go-test:
	@echo "  >  Running short tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -mod=readonly -short -race ./...

test-all: go-test-all
go-test-all:
	@echo "  >  Running all tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -mod=readonly ./...

go-test-coverage:
	@echo "  >  Running tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -mod=readonly -short -coverprofile=coverage.txt -covermode=atomic ./... 


verify: verify-gosec 

verify-gosec: download-gosec
verify-gosec:
	@echo "  >  Run gosec"
	@./build/tools/gosec/gosec -conf gosec.json ./...


export-coverage:
	@-$(MAKE) go-test-coverage && .github/tools/codecov.sh


download-tools: download-gosec

download-gosec:
	@.github/tools/download-gosec.sh