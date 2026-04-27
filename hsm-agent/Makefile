.PHONY: build build-linux build-mac build-windows clean test

build:
	go build -o bin/hsm-agent .

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/hsm-agent-linux-amd64 .

build-mac:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o bin/hsm-agent-darwin-arm64 .

# Requires mingw-w64: brew install mingw-w64 (macOS) or apt-get install gcc-mingw-w64 (Linux)
build-windows:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o bin/hsm-agent-windows-amd64.exe .

clean:
	rm -rf bin/

test:
	go test -v ./...
