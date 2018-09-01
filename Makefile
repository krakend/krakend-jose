DEP_VERSION=0.5.0
OS := $(shell uname | tr '[:upper:]' '[:lower:]')

all: deps test

prepare:
	@echo "Installing dep..."
	@curl -L -s https://github.com/golang/dep/releases/download/v${DEP_VERSION}/dep-${OS}-amd64 -o ${GOPATH}/bin/dep
	@chmod a+x ${GOPATH}/bin/dep

deps:
	dep ensure -v
	dep status

test:
	go test -cover ./...