# Multi-Aggregator Simulation - SMT Benchmark

This project provides a benchmarking tool for the Sparse Merkle Tree (SMT) data structure used in the blockchain aggregator. It generates and inserts 100,000 cryptographically valid commitments directly into an in-memory SMT to measure performance.

## Overview

The benchmark simulates the core data structure operations of the aggregator without the overhead of the full service stack. It:

1. Generates cryptographically valid commitments with proper secp256k1 signatures
2. Builds a Sparse Merkle Tree with these commitments
3. Calculates the root hash
4. Measures performance at each stage

## Features

- **Valid Cryptography**: All commitments use real secp256k1 key pairs and signatures
- **Proper Data Format**: Follows the exact format used by the production aggregator:
  - Request IDs: SHA256(publicKey || stateHash) with "0000" algorithm prefix
  - Transaction hashes: Random 32-byte values with "0000" prefix
  - Signatures: 65-byte format (R || S || V)
  - CBOR encoding for authenticators
- **Memory Tracking**: Reports memory usage at each phase
- **Performance Metrics**: Measures throughput in commits/second and leaves/second

## Quick Start

### Prerequisites

- Go 1.24 or later
- Make (optional, for using Makefile)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd multi_aggregator_sim

# Install dependencies
make deps
# OR
go mod download
```

### Running the Benchmark

By default, the benchmark runs with just **1 commitment** for quick testing. You can specify any number of commitments using various methods:

#### Using Make

```bash
# Run with default (1 commitment)
make benchmark

# Run with specific number of commitments
make benchmark-n N=1000
make benchmark-n N=100000

# Predefined configurations
make benchmark-10k    # 10,000 commitments
make benchmark-100k   # 100,000 commitments
make benchmark-1m     # 1,000,000 commitments
```

#### Direct Execution

```bash
# Default (1 commitment)
./bin/smt-benchmark-standalone

# With positional argument
./bin/smt-benchmark-standalone 1000

# With named flag
./bin/smt-benchmark-standalone -n 1000
./bin/smt-benchmark-standalone --count 1000
```

#### Using Docker

```bash
# Default (1 commitment)
make docker-run

# With specific number
make docker-benchmark-n N=1000

# Using docker directly
docker run --rm smt-benchmark 1000

# Using docker-compose with environment variable
NUM_COMMITMENTS=1000 docker-compose up

# Using docker-compose run
docker-compose run smt-benchmark /app/bin/smt-benchmark-standalone 1000
```

## Benchmark Programs

The project includes three benchmark implementations:

1. **Simple Benchmark** (`cmd/smt-benchmark/main.go`)
   - Basic implementation with simplified SMT
   - Good for understanding the structure

2. **Standalone Benchmark** (`cmd/smt-benchmark/standalone/main.go`)
   - Complete implementation with proper SMT structure
   - Default benchmark with detailed metrics

3. **Advanced Benchmark** (`cmd/smt-benchmark/advanced/main.go`)
   - Uses the reference implementation's packages
   - Most accurate but requires the aggregator-go dependencies

## Performance Results

Expected performance on modern hardware:

- **1 commitment**: < 10ms total time
- **1,000 commitments**: ~100-200ms
- **10,000 commitments**: ~1-2 seconds
- **100,000 commitments**: ~10-20 seconds
- **1,000,000 commitments**: ~100-200 seconds

Typical throughput:
- **Commitment Generation**: ~10,000-20,000 commits/sec
- **SMT Building**: ~100,000-200,000 leaves/sec
- **Root Calculation**: < 1 second for 100,000 leaves
- **Memory Usage**: ~500-1000 MB for 100,000 commitments

## Architecture

The benchmark follows the exact commitment structure from the production aggregator:

```go
type Commitment struct {
    RequestID       string          // SHA256(pubKey || stateHash) with prefix
    TransactionHash string          // Random hash with "0000" prefix
    Authenticator   Authenticator   // Cryptographic proof
}

type Authenticator struct {
    Algorithm string  // "secp256k1"
    PublicKey []byte  // 33-byte compressed
    Signature []byte  // 65-byte (R || S || V)
    StateHash string  // Hash with "0000" prefix
}
```

## Implementation Details

### Leaf Value Calculation

For each commitment, the leaf value is calculated as:
1. CBOR encode authenticator as array: `[algorithm, publicKey, signature, stateHash]`
2. Calculate: `SHA256(authenticatorCBOR || transactionHash)`
3. Add algorithm prefix: `"0000" + hex(hash)`

### Path Derivation

SMT paths are derived from request IDs by prefixing with "01" to preserve leading zeros.

## Command Line Usage

The benchmark programs accept the number of commitments in multiple ways:

```
Usage: smt-benchmark-standalone [options] [number_of_commitments]

Options:
  -n, --count  Number of commitments to generate (default: 1)

Examples:
  smt-benchmark-standalone              # Run with 1 commitment
  smt-benchmark-standalone 1000         # Run with 1000 commitments
  smt-benchmark-standalone -n 5000      # Run with 5000 commitments
  smt-benchmark-standalone --count 100  # Run with 100 commitments
```

## Development

### Building

```bash
# Build all benchmarks
make build

# Run tests
make test

# Format code
make fmt

# Clean build artifacts
make clean
```

### Adding New Benchmarks

To add a new benchmark variant:
1. Create a new file in `cmd/smt-benchmark/`
2. Implement the benchmark following the existing patterns
3. Update the Makefile with a new target

## Future Enhancements

- Multi-aggregator simulation with network delays
- Byzantine fault testing
- Consensus integration benchmarks
- Distributed SMT synchronization