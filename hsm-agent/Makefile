.PHONY: build build-linux build-mac clean test

build:
	go build -o bin/hsm-agent .

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/hsm-agent-linux-amd64 .

build-mac:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o bin/hsm-agent-darwin-arm64 .

clean:
	rm -rf bin/

test:
	go test -v ./...
