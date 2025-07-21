package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

// Constants for the benchmark
const (
	defaultCommitments = 1
	defaultThreads     = 1
	batchSize          = 1000
	algorithmID        = "secp256k1"
	sha256Prefix       = "0000" // Algorithm prefix for SHA256
)

// ThreadResult holds the benchmark results for a single thread
type ThreadResult struct {
	ThreadID           int
	NumCommitments     int
	GenerationTime     time.Duration
	SMTBuildTime       time.Duration
	RootCalculationTime time.Duration
	TotalTime          time.Duration
	RootHash           string
	Error              error
}

// AggregatedResults holds the combined results from all threads
type AggregatedResults struct {
	TotalCommitments    int
	TotalThreads        int
	TotalGenerationTime time.Duration
	TotalSMTBuildTime   time.Duration
	TotalRootCalcTime   time.Duration
	WallClockTime       time.Duration
	ThreadResults       []ThreadResult
	AvgCommitsPerSec    float64
	TotalCommitsPerSec  float64
}

// Commitment represents a state transition commitment
type Commitment struct {
	RequestID       string
	TransactionHash string
	Authenticator   Authenticator
}

// Authenticator contains the cryptographic proof
type Authenticator struct {
	Algorithm string
	PublicKey []byte
	Signature []byte
	StateHash string
}

// LeafNode represents a leaf in the SMT
type LeafNode struct {
	Path  []byte
	Value []byte
}

// BranchNode represents a branch in the SMT
type BranchNode struct {
	Left  interface{} // Can be *BranchNode, *LeafNode, or nil
	Right interface{} // Can be *BranchNode, *LeafNode, or nil
	hash  []byte      // Cached hash
}

// SparseMerkleTree represents the SMT structure
type SparseMerkleTree struct {
	root   interface{} // Can be *BranchNode, *LeafNode, or nil
	leaves map[string]*LeafNode
	mu     sync.RWMutex // Thread-safe operations
}

// NewSparseMerkleTree creates a new SMT
func NewSparseMerkleTree() *SparseMerkleTree {
	return &SparseMerkleTree{
		leaves: make(map[string]*LeafNode),
	}
}

// AddLeaf adds a leaf to the tree (thread-safe)
func (smt *SparseMerkleTree) AddLeaf(pathHex string, value []byte) {
	smt.mu.Lock()
	defer smt.mu.Unlock()
	
	path, _ := hex.DecodeString(pathHex)
	leaf := &LeafNode{Path: path, Value: value}
	smt.leaves[pathHex] = leaf
}

// BuildTree constructs the merkle tree from all added leaves
func (smt *SparseMerkleTree) BuildTree() {
	smt.mu.Lock()
	defer smt.mu.Unlock()
	
	if len(smt.leaves) == 0 {
		return
	}
	
	// Convert map to sorted slice for deterministic tree building
	var leaves []*LeafNode
	for _, leaf := range smt.leaves {
		leaves = append(leaves, leaf)
	}
	
	// Sort by path for deterministic ordering
	sort.Slice(leaves, func(i, j int) bool {
		return hex.EncodeToString(leaves[i].Path) < hex.EncodeToString(leaves[j].Path)
	})
	
	// Build tree recursively
	smt.root = smt.buildSubtree(leaves, 0)
}

func (smt *SparseMerkleTree) buildSubtree(leaves []*LeafNode, depth int) interface{} {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	
	// Split leaves based on bit at current depth
	mid := len(leaves) / 2
	
	branch := &BranchNode{
		Left:  smt.buildSubtree(leaves[:mid], depth+1),
		Right: smt.buildSubtree(leaves[mid:], depth+1),
	}
	
	return branch
}

// CalculateRoot computes the root hash of the tree
func (smt *SparseMerkleTree) CalculateRoot() []byte {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	
	if smt.root == nil {
		return make([]byte, 32)
	}
	return smt.calculateNodeHash(smt.root)
}

func (smt *SparseMerkleTree) calculateNodeHash(node interface{}) []byte {
	switch n := node.(type) {
	case *LeafNode:
		h := sha256.New()
		h.Write([]byte{0x00}) // Leaf prefix
		h.Write(n.Path)
		h.Write(n.Value)
		return h.Sum(nil)
		
	case *BranchNode:
		if n.hash != nil {
			return n.hash
		}
		
		h := sha256.New()
		h.Write([]byte{0x01}) // Branch prefix
		
		leftHash := make([]byte, 32)
		if n.Left != nil {
			leftHash = smt.calculateNodeHash(n.Left)
		}
		h.Write(leftHash)
		
		rightHash := make([]byte, 32)
		if n.Right != nil {
			rightHash = smt.calculateNodeHash(n.Right)
		}
		h.Write(rightHash)
		
		n.hash = h.Sum(nil)
		return n.hash
		
	default:
		return make([]byte, 32)
	}
}

// generateValidCommitment generates a cryptographically valid commitment
func generateValidCommitment(threadID, index int) (*Commitment, error) {
	// Generate a new secp256k1 key pair
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	
	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	
	// Generate random state hash (32 bytes)
	stateHashBytes := make([]byte, 32)
	if _, err := rand.Read(stateHashBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state hash: %w", err)
	}
	stateHashImprint := sha256Prefix + hex.EncodeToString(stateHashBytes)
	
	// Calculate request ID: SHA256(publicKey || stateHashImprint)
	requestIDHasher := sha256.New()
	requestIDHasher.Write(pubKeyBytes)
	requestIDHasher.Write([]byte(stateHashImprint))
	requestIDBytes := requestIDHasher.Sum(nil)
	requestID := sha256Prefix + hex.EncodeToString(requestIDBytes)
	
	// Generate random transaction hash (32 bytes)
	txHashBytes := make([]byte, 32)
	if _, err := rand.Read(txHashBytes); err != nil {
		return nil, fmt.Errorf("failed to generate transaction hash: %w", err)
	}
	transactionHash := sha256Prefix + hex.EncodeToString(txHashBytes)
	
	// Sign the transaction hash (without prefix)
	signature := ecdsa.Sign(privKey, txHashBytes)
	
	// Convert signature to 65-byte format (R || S || V)
	sigBytes := signature.Serialize()
	// Add recovery ID as the 65th byte (simplified, using 0)
	sigBytesWithRecovery := append(sigBytes, 0)
	
	commitment := &Commitment{
		RequestID:       requestID,
		TransactionHash: transactionHash,
		Authenticator: Authenticator{
			Algorithm: algorithmID,
			PublicKey: pubKeyBytes,
			Signature: sigBytesWithRecovery,
			StateHash: stateHashImprint,
		},
	}
	
	return commitment, nil
}

// calculateLeafValue calculates the SMT leaf value for a commitment
func calculateLeafValue(commitment *Commitment) ([]byte, error) {
	// CBOR encode the authenticator as array
	authenticatorArray := []interface{}{
		commitment.Authenticator.Algorithm,
		commitment.Authenticator.PublicKey,
		commitment.Authenticator.Signature,
		commitment.Authenticator.StateHash,
	}
	
	authenticatorCBOR, err := cbor.Marshal(authenticatorArray)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR encode authenticator: %w", err)
	}
	
	// Calculate leaf value: SHA256(authenticatorCBOR || transactionHashImprint)
	leafHasher := sha256.New()
	leafHasher.Write(authenticatorCBOR)
	leafHasher.Write([]byte(commitment.TransactionHash))
	leafHash := leafHasher.Sum(nil)
	
	// Return with algorithm prefix
	leafValue := sha256Prefix + hex.EncodeToString(leafHash)
	return []byte(leafValue), nil
}

// getPath converts request ID to SMT path by prefixing with 01
func getPath(requestID string) string {
	return "01" + requestID
}

// runThreadBenchmark runs the benchmark for a single thread
func runThreadBenchmark(threadID, numCommitments int, wg *sync.WaitGroup, results chan<- ThreadResult) {
	defer wg.Done()
	
	result := ThreadResult{
		ThreadID:       threadID,
		NumCommitments: numCommitments,
	}
	
	startTotal := time.Now()
	
	// Phase 1: Generate commitments
	startGen := time.Now()
	
	commitments := make([]*Commitment, numCommitments)
	leafValues := make(map[string][]byte)
	
	for i := 0; i < numCommitments; i++ {
		commitment, err := generateValidCommitment(threadID, i)
		if err != nil {
			result.Error = fmt.Errorf("thread %d: failed to generate commitment %d: %w", threadID, i, err)
			results <- result
			return
		}
		
		leafValue, err := calculateLeafValue(commitment)
		if err != nil {
			result.Error = fmt.Errorf("thread %d: failed to calculate leaf value %d: %w", threadID, i, err)
			results <- result
			return
		}
		
		commitments[i] = commitment
		path := getPath(commitment.RequestID)
		leafValues[path] = leafValue
	}
	
	result.GenerationTime = time.Since(startGen)
	
	// Phase 2: Build Sparse Merkle Tree
	smt := NewSparseMerkleTree()
	
	startSMT := time.Now()
	
	// Add leaves to SMT
	for path, value := range leafValues {
		smt.AddLeaf(path, value)
	}
	
	// Build the tree structure
	smt.BuildTree()
	
	result.SMTBuildTime = time.Since(startSMT)
	
	// Phase 3: Calculate root hash
	startRoot := time.Now()
	
	root := smt.CalculateRoot()
	
	result.RootCalculationTime = time.Since(startRoot)
	result.RootHash = sha256Prefix + hex.EncodeToString(root)
	result.TotalTime = time.Since(startTotal)
	
	results <- result
}

func parseArgs() (int, int) {
	var numCommitments, numThreads int
	
	// Define flags
	flag.IntVar(&numCommitments, "n", defaultCommitments, "Number of commitments to generate per thread")
	flag.IntVar(&numCommitments, "count", defaultCommitments, "Number of commitments to generate per thread")
	flag.IntVar(&numThreads, "t", defaultThreads, "Number of threads to run")
	flag.IntVar(&numThreads, "threads", defaultThreads, "Number of threads to run")
	flag.Parse()
	
	// Check for positional arguments
	args := flag.Args()
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid number of commitments: %s\n", args[0])
			printUsage()
			os.Exit(1)
		}
		numCommitments = n
	}
	
	if len(args) > 1 {
		t, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid number of threads: %s\n", args[1])
			printUsage()
			os.Exit(1)
		}
		numThreads = t
	}
	
	// Validate inputs
	if numCommitments <= 0 {
		fmt.Fprintf(os.Stderr, "Error: Number of commitments must be positive\n")
		os.Exit(1)
	}
	
	if numThreads <= 0 {
		fmt.Fprintf(os.Stderr, "Error: Number of threads must be positive\n")
		os.Exit(1)
	}
	
	// Set thread count to CPU count if requested
	if numThreads > runtime.NumCPU() {
		fmt.Printf("Warning: Thread count (%d) exceeds CPU count (%d)\n", numThreads, runtime.NumCPU())
	}
	
	return numCommitments, numThreads
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [commitments_per_thread] [thread_count]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fmt.Fprintf(os.Stderr, "  -n, --count     Number of commitments per thread (default: %d)\n", defaultCommitments)
	fmt.Fprintf(os.Stderr, "  -t, --threads   Number of threads (default: %d)\n", defaultThreads)
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  %s                    # 1 commitment, 1 thread\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s 1000               # 1000 commitments, 1 thread\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s 1000 4             # 1000 commitments per thread, 4 threads\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -n 1000 -t 8       # 1000 commitments per thread, 8 threads\n", os.Args[0])
}

func printMemStats(phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("  Memory stats (%s):\n", phase)
	fmt.Printf("    Alloc: %d MB\n", m.Alloc/1024/1024)
	fmt.Printf("    TotalAlloc: %d MB\n", m.TotalAlloc/1024/1024)
	fmt.Printf("    Sys: %d MB\n", m.Sys/1024/1024)
	fmt.Printf("    NumGC: %d\n", m.NumGC)
}

func aggregateResults(results []ThreadResult, wallClockTime time.Duration) AggregatedResults {
	agg := AggregatedResults{
		ThreadResults: results,
		WallClockTime: wallClockTime,
	}
	
	for _, r := range results {
		if r.Error == nil {
			agg.TotalCommitments += r.NumCommitments
			agg.TotalThreads++
			agg.TotalGenerationTime += r.GenerationTime
			agg.TotalSMTBuildTime += r.SMTBuildTime
			agg.TotalRootCalcTime += r.RootCalculationTime
		}
	}
	
	if agg.TotalThreads > 0 {
		avgGenTime := agg.TotalGenerationTime.Seconds() / float64(agg.TotalThreads)
		avgSMTTime := agg.TotalSMTBuildTime.Seconds() / float64(agg.TotalThreads)
		agg.AvgCommitsPerSec = float64(agg.TotalCommitments) / (avgGenTime + avgSMTTime)
		agg.TotalCommitsPerSec = float64(agg.TotalCommitments) / wallClockTime.Seconds()
	}
	
	return agg
}

func main() {
	// Parse command line arguments
	numCommitments, numThreads := parseArgs()
	
	// Set GOMAXPROCS to use all available CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// Run garbage collection before benchmark
	runtime.GC()
	
	fmt.Printf("Multi-threaded SMT Benchmark\n")
	fmt.Printf("================================================\n")
	fmt.Printf("Threads: %d\n", numThreads)
	fmt.Printf("Commitments per thread: %d\n", numCommitments)
	fmt.Printf("Total commitments: %d\n", numCommitments*numThreads)
	fmt.Printf("CPU cores available: %d\n", runtime.NumCPU())
	fmt.Printf("================================================\n\n")
	
	// Create channels and wait group
	var wg sync.WaitGroup
	results := make(chan ThreadResult, numThreads)
	
	// Record start time
	startTime := time.Now()
	
	// Launch threads
	fmt.Printf("Launching %d threads...\n", numThreads)
	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go runThreadBenchmark(i, numCommitments, &wg, results)
	}
	
	// Close results channel when all threads complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	var threadResults []ThreadResult
	var completedThreads int32
	
	for result := range results {
		threadResults = append(threadResults, result)
		atomic.AddInt32(&completedThreads, 1)
		
		if result.Error != nil {
			fmt.Printf("Thread %d failed: %v\n", result.ThreadID, result.Error)
		} else {
			fmt.Printf("Thread %d completed: %d commits in %v (%.2f commits/sec)\n",
				result.ThreadID, result.NumCommitments, result.TotalTime,
				float64(result.NumCommitments)/result.TotalTime.Seconds())
		}
	}
	
	wallClockTime := time.Since(startTime)
	
	// Print memory stats
	fmt.Println()
	printMemStats("After all threads completed")
	
	// Aggregate results
	fmt.Printf("\n================================================\n")
	fmt.Printf("Per-Thread Results:\n")
	fmt.Printf("================================================\n")
	
	for _, r := range threadResults {
		if r.Error == nil {
			fmt.Printf("Thread %d:\n", r.ThreadID)
			fmt.Printf("  Commitments: %d\n", r.NumCommitments)
			fmt.Printf("  Generation: %v (%.2f commits/sec)\n", 
				r.GenerationTime, float64(r.NumCommitments)/r.GenerationTime.Seconds())
			fmt.Printf("  SMT Build: %v (%.2f leaves/sec)\n", 
				r.SMTBuildTime, float64(r.NumCommitments)/r.SMTBuildTime.Seconds())
			fmt.Printf("  Root Calc: %v\n", r.RootCalculationTime)
			fmt.Printf("  Total: %v\n", r.TotalTime)
			fmt.Printf("  Root Hash: %s\n", r.RootHash)
			fmt.Println()
		}
	}
	
	// Print aggregated results
	agg := aggregateResults(threadResults, wallClockTime)
	
	fmt.Printf("================================================\n")
	fmt.Printf("Aggregated Results:\n")
	fmt.Printf("================================================\n")
	fmt.Printf("Total threads: %d (successful: %d)\n", numThreads, agg.TotalThreads)
	fmt.Printf("Total commitments: %d\n", agg.TotalCommitments)
	fmt.Printf("Wall clock time: %v\n", agg.WallClockTime)
	fmt.Printf("\nCumulative thread time:\n")
	fmt.Printf("  Generation: %v\n", agg.TotalGenerationTime)
	fmt.Printf("  SMT Build: %v\n", agg.TotalSMTBuildTime)
	fmt.Printf("  Root Calc: %v\n", agg.TotalRootCalcTime)
	fmt.Printf("\nThroughput:\n")
	fmt.Printf("  Average per thread: %.2f commits/sec\n", agg.AvgCommitsPerSec)
	fmt.Printf("  Total (parallel): %.2f commits/sec\n", agg.TotalCommitsPerSec)
	fmt.Printf("  Speedup: %.2fx\n", agg.TotalCommitsPerSec/(agg.AvgCommitsPerSec/float64(agg.TotalThreads)))
	
	// Final memory stats
	fmt.Printf("\nFinal ")
	printMemStats("End of benchmark")
}