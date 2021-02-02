files := $(shell find . -path ./build -prune -o -name '*.go' -print)
pkgs := $(shell go list ./... | grep -v test)

os := $(shell uname)
ifeq ("$(os)", "Linux")
	GOOS = linux
else ifeq ("$(os)", "Darwin")
	GOOS = darwin
endif
GOARCH ?= amd64

projectDir := $(realpath $(dir $(firstword $(MAKEFILE_LIST))))
buildDir := $(projectDir)/build
version := 0.0.1
image := production-readiness:v$(version)

.PHONY: setup
setup: install-tools
	@echo "== setup"

.PHONY: check
check: vet lint checkformat

.PHONY: vet
vet:
	@echo "== vet $(pkgs)"
	@go vet $(pkgs)

.PHONY: lint
lint:
	@echo "== lint"
	@for pkg in $(pkgs); do \
		golint -set_exit_status $$pkg || exit 1 ; \
	done;

.PHONY: checkformat
checkformat:
	@echo "== check formatting"
ifneq "$(shell goimports -l $(files))" ""
	@echo "code needs formatting. Run make format"
	@exit 1
endif

.PHONY: format
format:
	@echo "== format"
	@goimports -w $(files)
	@sync

.PHONY: test
test:
	@echo "== run unit tests"
	go test -v $(pkgs)

.PHONY: build
build: check test
	@echo "build"
	 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(buildDir)/bin/production-readiness -v github.com/coreeng/production-readiness/production-readiness/cmd

.PHONY: install
install: build
	@echo "== install"
	cp -v $(buildDir)/bin/production-readiness $(shell go env GOPATH)/bin/production-readiness

.PHONY: functional-test
functional-test:
	@echo "== functional-test"
	IMAGE_UNDER_TEST=$(image) ginkgo -r --v --progress test/functional

.PHONY: integrated-test
integrated-test:
	@echo "== integrated-test"
	IMAGE_UNDER_TEST=$(image) ginkgo -r --v --progress test/integrated

.PHONY: clean
clean:
	@echo "== clean"
	rm -rf $(buildDir)

.PHONY: docker
docker: build
	@echo "== docker"
	docker build -t production-readiness ${projectDir}/

.PHONY: download
download:
	@echo Download go.mod dependencies
	@go mod download

.PHONY: install-tools
install-tools: download
	@echo Installing tools from tools.go
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %