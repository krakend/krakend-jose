all: test build

generate:
	go generate ./...

test: generate
	go test ./...