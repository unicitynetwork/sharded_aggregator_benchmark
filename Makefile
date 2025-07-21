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
	@go build -o $(BUILD_DIR)/smt-benchmark-threaded ./cmd/smt-benchmark/threaded/main.go
	@go build -o $(BUILD_DIR)/smt-benchmark-threaded-aggregator ./cmd/smt-benchmark/threaded-aggregator/main.go
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

# Run threaded benchmark
benchmark-threaded: build
	@echo "Running threaded SMT benchmark..."
	@./$(BUILD_DIR)/smt-benchmark-threaded $(ARGS)

# Run threaded benchmark with custom parameters
benchmark-threaded-nt: build
	@if [ -z "$(N)" ] || [ -z "$(T)" ]; then \
		echo "Error: Please specify N=<commitments> T=<threads> (e.g., make benchmark-threaded-nt N=1000 T=4)"; \
		exit 1; \
	fi
	@echo "Running threaded benchmark with $(N) commitments on $(T) threads..."
	@./$(BUILD_DIR)/smt-benchmark-threaded -n $(N) -t $(T)

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

# Threaded benchmark presets
benchmark-threaded-4: build
	@echo "Running threaded benchmark with 4 threads (1000 commits each)..."
	@./$(BUILD_DIR)/smt-benchmark-threaded 1000 4

benchmark-threaded-8: build
	@echo "Running threaded benchmark with 8 threads (1000 commits each)..."
	@./$(BUILD_DIR)/smt-benchmark-threaded 1000 8

benchmark-threaded-cpu: build
	@echo "Running threaded benchmark with CPU count threads..."
	@./$(BUILD_DIR)/smt-benchmark-threaded -n 1000 -t $$(nproc)

# Threaded benchmark with aggregator submission
benchmark-aggregator: build
	@echo "Running threaded benchmark with aggregator submission..."
	@./$(BUILD_DIR)/smt-benchmark-threaded-aggregator -s $(ARGS)

benchmark-aggregator-nt: build
	@if [ -z "$(N)" ] || [ -z "$(T)" ]; then \
		echo "Error: Please specify N=<commitments> T=<threads> (e.g., make benchmark-aggregator-nt N=1000 T=4)"; \
		exit 1; \
	fi
	@echo "Running aggregator benchmark with $(N) commitments on $(T) threads..."
	@./$(BUILD_DIR)/smt-benchmark-threaded-aggregator -n $(N) -t $(T) -s

# Duration-based benchmarks
benchmark-duration: build
	@if [ -z "$(D)" ]; then \
		echo "Error: Please specify D=<duration> (e.g., make benchmark-duration D=1s)"; \
		exit 1; \
	fi
	@echo "Running duration benchmark for $(D)..."
	@./$(BUILD_DIR)/smt-benchmark-threaded-aggregator -d $(D) $(ARGS)

benchmark-duration-1s: build
	@echo "Running benchmark for 1 second with 4 threads..."
	@./$(BUILD_DIR)/smt-benchmark-threaded-aggregator -d 1s -t 4

benchmark-duration-aggregator: build
	@if [ -z "$(D)" ] || [ -z "$(T)" ]; then \
		echo "Error: Please specify D=<duration> T=<threads> (e.g., make benchmark-duration-aggregator D=1s T=4)"; \
		exit 1; \
	fi
	@echo "Running duration benchmark for $(D) with $(T) threads and aggregator submission..."
	@./$(BUILD_DIR)/smt-benchmark-threaded-aggregator -d $(D) -t $(T) -s

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