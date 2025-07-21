#!/bin/bash

# Script to run Docker benchmark command in a loop
# Press Ctrl+C to stop
# Usage: ./run_benchmark.sh [threads]
# Example: ./run_benchmark.sh 16

# Default number of threads
THREADS=${1:-8}

# Validate threads parameter
if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [ "$THREADS" -le 0 ]; then
    echo "Error: Threads must be a positive integer"
    echo "Usage: $0 [threads]"
    echo "Example: $0 16"
    exit 1
fi

echo "Starting continuous benchmark loop with $THREADS threads..."
echo "Press Ctrl+C to stop"
echo ""

# Counter to track iterations
counter=1

# Trap Ctrl+C and provide a clean exit message
trap 'echo -e "\n\nBenchmark loop stopped after $counter iterations."; exit 0' INT

# Main loop
while true; do
    echo "=== Running benchmark iteration $counter (threads: $THREADS) ==="
    docker run --rm smt-benchmark aggregator -d 1s -t $THREADS -s
    
    echo "Completed iteration $counter"
    echo ""
    
    ((counter++))
    
    # Small delay between iterations (optional - you can remove this if you want continuous execution)
    sleep 1
done
