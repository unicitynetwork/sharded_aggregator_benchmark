.PHONY: build test clean benchmark-simple benchmark-standalone benchmark-all deps

# Build variables
BUILD_DIR=bin

# Default target
all: build

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Build all benchmarks
build: deps
	@echo "Building benchmarks..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/smt-benchmark-simple ./cmd/smt-benchmark/main.go
	@go build -o $(BUILD_DIR)/smt-benchmark-standalone ./cmd/smt-benchmark/standalone/main.go
	@echo "✓ Build complete"

# Run simple benchmark
benchmark-simple: build
	@echo "Running simple SMT benchmark..."
	@./$(BUILD_DIR)/smt-benchmark-simple $(ARGS)

# Run standalone benchmark
benchmark-standalone: build
	@echo "Running standalone SMT benchmark..."
	@./$(BUILD_DIR)/smt-benchmark-standalone $(ARGS)

# Run all benchmarks
benchmark-all: benchmark-simple benchmark-standalone

# Run the default benchmark (standalone version with 1 commitment by default)
benchmark: build
	@echo "Running standalone SMT benchmark with default (1) commitment..."
	@./$(BUILD_DIR)/smt-benchmark-standalone

# Run benchmark with custom number of commitments
benchmark-n: build
	@if [ -z "$(N)" ]; then \
		echo "Error: Please specify N=<number> (e.g., make benchmark-n N=1000)"; \
		exit 1; \
	fi
	@echo "Running benchmark with $(N) commitments..."
	@./$(BUILD_DIR)/smt-benchmark-standalone $(N)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@go clean

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run with different commitment counts
benchmark-10k: build
	@echo "Running benchmark with 10,000 commitments..."
	@./$(BUILD_DIR)/smt-benchmark-standalone 10000

benchmark-100k: build
	@echo "Running benchmark with 100,000 commitments..."
	@./$(BUILD_DIR)/smt-benchmark-standalone 100000

benchmark-1m: build
	@echo "Running benchmark with 1,000,000 commitments..."
	@./$(BUILD_DIR)/smt-benchmark-standalone 1000000

# Docker commands
docker-build:
	@echo "Building Docker image..."
	@docker build -t smt-benchmark .

docker-run: docker-build
	@echo "Running benchmark in Docker..."
	@docker run --rm smt-benchmark $(ARGS)

docker-benchmark: docker-run

# Run Docker benchmark with custom number of commitments
docker-benchmark-n: docker-build
	@if [ -z "$(N)" ]; then \
		echo "Error: Please specify N=<number> (e.g., make docker-benchmark-n N=1000)"; \
		exit 1; \
	fi
	@echo "Running Docker benchmark with $(N) commitments..."
	@docker run --rm smt-benchmark $(N)

docker-compose-up:
	@echo "Running benchmark with docker-compose..."
	@docker-compose up --build

docker-compose-down:
	@echo "Stopping docker-compose..."
	@docker-compose down

# Run benchmark using Docker if Go is not installed
run-benchmark:
	@if command -v go > /dev/null 2>&1; then \
		echo "Running benchmark with Go..."; \
		make benchmark; \
	else \
		echo "Go not found, running benchmark with Docker..."; \
		make docker-run; \
	fi