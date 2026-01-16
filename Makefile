.PHONY: build clean test install lint fmt vet run help

BINARY_NAME=k8s-security-auditor
BUILD_DIR=bin
GO_FILES=$(shell find . -name '*.go' -type f)

help: ## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

build-all: ## Build for all platforms
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Building for macOS (Intel)..."
	@GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	@echo "Building for macOS (ARM)..."
	@GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Built all binaries in $(BUILD_DIR)/"

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@go clean
	@echo "Cleaned"

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

install: build ## Install the binary
	@echo "Installing $(BINARY_NAME)..."
	@go install .
	@echo "Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run ./...

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -s -w $(GO_FILES)

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

run: build ## Build and run
	@$(BUILD_DIR)/$(BINARY_NAME) -v

run-json: build ## Build and run with JSON output
	@$(BUILD_DIR)/$(BINARY_NAME) -o json

run-sarif: build ## Build and run with SARIF output
	@$(BUILD_DIR)/$(BINARY_NAME) -o sarif -f audit-results.sarif

example: build ## Run example audit (dry-run fix)
	@$(BUILD_DIR)/$(BINARY_NAME) --fix --dry-run --diff -v

python-plugin: build ## Run with Python plugin
	@$(BUILD_DIR)/$(BINARY_NAME) -o json -f audit-results.json
	@python3 plugins/agentic_reasoner.py --input audit-results.json --output enhanced-report.md
	@echo "Enhanced report: enhanced-report.md"

docker-build: ## Build Docker image
	@docker build -t $(BINARY_NAME):latest .

docker-run: ## Run in Docker
	@docker run --rm -v ~/.kube:/root/.kube $(BINARY_NAME):latest
