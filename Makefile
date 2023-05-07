VERSION=v0.0.1

bin: bin/gate_darwin bin/gate_linux bin/gate_windows

bin/gate_darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/gate_darwin cmd/gate/*.go
	openssl sha512 bin/gate_darwin > bin/gate_darwin.sha512

bin/gate_linux:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/gate_linux cmd/gate/*.go
	openssl sha512 bin/gate_linux > bin/gate_linux.sha512

bin/gate_windows:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/gate_windows cmd/gate/*.go
	openssl sha512 bin/gate_windows > bin/gate_windows.sha512

.PHONY: docker
docker:
	docker buildx build --build-arg VERSION=$(VERSION) --platform linux/amd64,linux/arm64 -t registry.lestak.sh/gate:latest --push .