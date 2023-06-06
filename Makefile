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
setup: check-system-dependencies install-tools
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
	go run github.com/onsi/ginkgo/v2/ginkgo --skip-package test/integrated --junit-report=unit-tests-report.xml -r --v

.PHONY: build
build: check test
	@echo "build"
	 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(buildDir)/bin/production-readiness -v github.com/coreeng/production-readiness/production-readiness/cmd

.PHONY: install
install: build
	@echo "== install"
	cp -v $(buildDir)/bin/production-readiness $(shell go env GOPATH)/bin/production-readiness

.PHONY: integrated-test
integrated-test:
	@echo "== integrated-test"
	go run github.com/onsi/ginkgo/v2/ginkgo --junit-report=integrated-tests-report.xml -r --v --show-node-events test/integrated

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
	@echo "== download go.mod dependencies"
	@go mod download

.PHONY: install-tools
install-tools: download
	@echo "== installing tools from tools.go"
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %

.PHONY: kind
kind:
	@echo "== creating kind cluster"
	$(projectDir)/create-kind-cluster.sh

.PHONY: check-system-dependencies
check-system-dependencies:
	@echo "== checking system dependencies"
ifeq (, $(shell which go))
	$(error "golang not found in PATH")
endif
ifeq (, $(shell which docker))
	$(error "docker not found in PATH")
endif
ifeq (, $(shell which kind))
	$(error "kind not found in PATH")
endif
ifeq (, $(shell which trivy))
	$(error "trivy not found in PATH")
endif
ifeq (, $(shell which kubectl))
	$(error "kubectl not found in PATH")
endif
