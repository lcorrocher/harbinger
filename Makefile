.PHONY: help build test build-test vet govulncheck clean

help:
	@echo "Available commands:"
	@echo "  make build-test   - Build Docker test image"
	@echo "  make test         - Run tests in Docker"
	@echo "  make vet          - Run go vet in Docker"
	@echo "  make govulncheck  - Run govulncheck in Docker"
	@echo "  make all          - Run test, vet, and govulncheck"
	@echo "  make build        - Build the production Docker image"
	@echo "  make clean        - Remove Docker test image"

build-test:
	docker build --target=builder -t harbinger-dev:latest .

test: build-test
	docker run --rm harbinger-dev:latest go test -race ./...

vet: build-test
	docker run --rm harbinger-dev:latest go vet ./...

govulncheck: build-test
	docker run --rm harbinger-dev:latest sh -c "go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./..."

all: test vet govulncheck

build:
	docker build -t harbinger:latest .

clean:
	docker rmi harbinger-dev:latest 2>/dev/null || true
