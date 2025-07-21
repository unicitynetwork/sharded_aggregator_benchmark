# Build stage
FROM golang:1.24-alpine AS builder

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

# Use ENTRYPOINT for the executable and CMD for default arguments
ENTRYPOINT ["/app/bin/smt-benchmark-standalone"]
CMD ["1"]