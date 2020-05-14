BINARY_NAME := $(shell basename "$(PWD)")
VERSION := $(shell git describe --tags --always)

GOBASE := $(shell pwd)
GOPATH := $(GOBASE)/vendor:$(GOBASE)
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard cmd/*.go)

LDFLAGS :=-ldflags "-w -X=github.com/pjbgf/zaz/cmd.gitcommit=$(VERSION) -extldflags -static"


all: build

build: go-compile

run: 
	@-$(GOBIN)/$(BINARY_NAME)

.PHONY: clean
clean:
	@-rm $(GOBIN)/$(BINARY_NAME) 2> /dev/null
	@-$(MAKE) go-clean


.PHONY: image
image: 
	@-$(MAKE) docker-build

.PHONY: push
push: 
	@-$(MAKE) docker-push


.PHONY: test
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


.PHONY: verify
verify: verify-gosec 

verify-gosec: download-gosec
verify-gosec:
	@echo "  >  Run gosec"
	@./build/tools/gosec/gosec -conf gosec.json ./...



export-coverage:
	@-$(MAKE) go-test-coverage && .github/tools/codecov.sh


.PHONY: download-tools
download-tools: download-gosec

download-gosec:
	@.github/tools/download-gosec.sh