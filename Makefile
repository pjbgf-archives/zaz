## Inspired on Makefile from https://kodfabrik.com/journal/a-good-makefile-for-go/

BINARY_NAME := $(shell basename "$(PWD)")
VERSION := $(shell git describe --tags --always)

GOBASE := $(shell pwd)
GOPATH := $(GOBASE)/vendor:$(GOBASE)
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard cmd/*.go)

GOSECNAME := "gosec_2.0.0_linux_amd64"

LDFLAGS :=-ldflags "-w -X=github.com/pjbgf/zaz/cmd.gitcommit=$(VERSION) -extldflags -static"


all: build

build: 
	@-$(MAKE) -s go-compile

run: 
	@-$(GOBIN)/$(BINARY_NAME)

clean:
	@-rm $(GOBIN)/$(BINARY_NAME) 2> /dev/null
	@-$(MAKE) go-clean

image: 
	@-$(MAKE) docker-build

push: 
	@-$(MAKE) docker-push


test: go-test


docker-build: 
	@echo "  >  Building image $(REGISTRY)/$(BINARY_NAME):$(VERSION)"
	@docker build -t $(REGISTRY)/$(BINARY_NAME):$(VERSION) .

docker-push: 
	@echo "  >  Building image $(REGISTRY)/$(BINARY_NAME):$(VERSION)"
	@docker build -t $(REGISTRY)/$(BINARY_NAME):$(VERSION) .

go-compile: go-get go-build

go-get:
	@echo "  >  Checking if there is any missing dependencies..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go get $(get)

go-build:
	@echo "  >  Building binary..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -a $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) $(GOFILES)

go-generate:
	@echo "  >  Generating dependency files..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go generate $(generate)

go-clean:
	@echo "  >  Cleaning build cache"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go clean

go-test:
	@echo "  >  Running tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -race ./...

go-test-coverage:
	@echo "  >  Running tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -race -coverprofile=coverage.txt -covermode=atomic ./... 


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