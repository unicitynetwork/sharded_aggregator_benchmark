# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the benchmarks
RUN make build

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binaries from builder
COPY --from=builder /app/bin /app/bin

# Set working directory
WORKDIR /app

# Create a simple script to handle different benchmark types
RUN echo '#!/bin/sh' > /app/run-benchmark.sh && \
    echo 'if [ "$1" = "threaded" ]; then' >> /app/run-benchmark.sh && \
    echo '  shift' >> /app/run-benchmark.sh && \
    echo '  exec /app/bin/smt-benchmark-threaded "$@"' >> /app/run-benchmark.sh && \
    echo 'elif [ "$1" = "simple" ]; then' >> /app/run-benchmark.sh && \
    echo '  shift' >> /app/run-benchmark.sh && \
    echo '  exec /app/bin/smt-benchmark-simple "$@"' >> /app/run-benchmark.sh && \
    echo 'else' >> /app/run-benchmark.sh && \
    echo '  exec /app/bin/smt-benchmark-standalone "$@"' >> /app/run-benchmark.sh && \
    echo 'fi' >> /app/run-benchmark.sh && \
    chmod +x /app/run-benchmark.sh

# Use the script as entrypoint
ENTRYPOINT ["/app/run-benchmark.sh"]
CMD ["1"]