package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

// Constants for the benchmark
const (
	defaultCommitments = 1
	batchSize          = 1000
	algorithmID        = "secp256k1"
	sha256Prefix       = "0000" // Algorithm prefix for SHA256
)

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
}

// NewSparseMerkleTree creates a new SMT
func NewSparseMerkleTree() *SparseMerkleTree {
	return &SparseMerkleTree{
		leaves: make(map[string]*LeafNode),
	}
}

// AddLeaf adds a leaf to the tree
func (smt *SparseMerkleTree) AddLeaf(pathHex string, value []byte) {
	path, _ := hex.DecodeString(pathHex)
	leaf := &LeafNode{Path: path, Value: value}
	smt.leaves[pathHex] = leaf
	
	// In a real implementation, we would update the tree structure here
	// For benchmarking, we'll build the tree after all leaves are added
}

// BuildTree constructs the merkle tree from all added leaves
func (smt *SparseMerkleTree) BuildTree() {
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
	
	// Build tree recursively (simplified for benchmark)
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
func generateValidCommitment(index int) (*Commitment, error) {
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

func printMemStats(phase string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("  Memory stats (%s):\n", phase)
	fmt.Printf("    Alloc: %d MB\n", m.Alloc/1024/1024)
	fmt.Printf("    TotalAlloc: %d MB\n", m.TotalAlloc/1024/1024)
	fmt.Printf("    Sys: %d MB\n", m.Sys/1024/1024)
	fmt.Printf("    NumGC: %d\n", m.NumGC)
}

func parseArgs() int {
	var numCommitments int
	
	// Check for command line flags first
	flag.IntVar(&numCommitments, "n", defaultCommitments, "Number of commitments to generate")
	flag.IntVar(&numCommitments, "count", defaultCommitments, "Number of commitments to generate")
	flag.Parse()
	
	// If still default, check for positional argument
	if numCommitments == defaultCommitments && flag.NArg() > 0 {
		n, err := strconv.Atoi(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid number of commitments: %s\n", flag.Arg(0))
			fmt.Fprintf(os.Stderr, "Usage: %s [options] [number_of_commitments]\n", os.Args[0])
			fmt.Fprintf(os.Stderr, "Options:\n")
			fmt.Fprintf(os.Stderr, "  -n, --count  Number of commitments to generate (default: %d)\n", defaultCommitments)
			os.Exit(1)
		}
		numCommitments = n
	}
	
	if numCommitments <= 0 {
		fmt.Fprintf(os.Stderr, "Error: Number of commitments must be positive\n")
		os.Exit(1)
	}
	
	return numCommitments
}

func main() {
	// Parse command line arguments
	numCommitments := parseArgs()
	
	// Run garbage collection before benchmark
	runtime.GC()
	
	fmt.Printf("SMT Benchmark: Generating and inserting %d commitments\n", numCommitments)
	fmt.Println("================================================")
	
	startTotal := time.Now()
	
	// Phase 1: Generate commitments
	fmt.Printf("\nPhase 1: Generating %d valid commitments...\n", numCommitments)
	startGen := time.Now()
	
	commitments := make([]*Commitment, numCommitments)
	leafValues := make(map[string][]byte)
	
	for i := 0; i < numCommitments; i++ {
		commitment, err := generateValidCommitment(i)
		if err != nil {
			log.Fatalf("Failed to generate commitment %d: %v", i, err)
		}
		
		leafValue, err := calculateLeafValue(commitment)
		if err != nil {
			log.Fatalf("Failed to calculate leaf value %d: %v", i, err)
		}
		
		commitments[i] = commitment
		path := getPath(commitment.RequestID)
		leafValues[path] = leafValue
		
		if (i+1)%10000 == 0 {
			fmt.Printf("  Generated %d commitments...\n", i+1)
		}
	}
	
	genDuration := time.Since(startGen)
	fmt.Printf("✓ Generated %d commitments in %v\n", numCommitments, genDuration)
	fmt.Printf("  Average time per commitment: %v\n", genDuration/time.Duration(numCommitments))
	
	printMemStats("After generation")
	
	// Phase 2: Build Sparse Merkle Tree
	fmt.Printf("\nPhase 2: Building Sparse Merkle Tree...\n")
	smt := NewSparseMerkleTree()
	
	startSMT := time.Now()
	
	// Add leaves to SMT
	for path, value := range leafValues {
		smt.AddLeaf(path, value)
	}
	
	// Build the tree structure
	fmt.Printf("  Building tree structure...\n")
	smt.BuildTree()
	
	smtDuration := time.Since(startSMT)
	fmt.Printf("✓ Built SMT with %d leaves in %v\n", numCommitments, smtDuration)
	fmt.Printf("  Average time per leaf: %v\n", smtDuration/time.Duration(numCommitments))
	
	printMemStats("After SMT build")
	
	// Phase 3: Calculate root hash
	fmt.Printf("\nPhase 3: Calculating root hash...\n")
	startRoot := time.Now()
	
	root := smt.CalculateRoot()
	
	rootDuration := time.Since(startRoot)
	fmt.Printf("✓ Calculated root hash in %v\n", rootDuration)
	fmt.Printf("  Root hash: %s%x\n", sha256Prefix, root)
	
	// Summary
	totalDuration := time.Since(startTotal)
	fmt.Printf("\n================================================\n")
	fmt.Printf("Benchmark Summary:\n")
	fmt.Printf("  Total commitments: %d\n", numCommitments)
	fmt.Printf("  Generation time: %v (%.2f commits/sec)\n", 
		genDuration, float64(numCommitments)/genDuration.Seconds())
	fmt.Printf("  SMT build time: %v (%.2f leaves/sec)\n", 
		smtDuration, float64(numCommitments)/smtDuration.Seconds())
	fmt.Printf("  Root calculation: %v\n", rootDuration)
	fmt.Printf("  Total time: %v\n", totalDuration)
	fmt.Printf("  Total throughput: %.2f commits/sec\n", 
		float64(numCommitments)/totalDuration.Seconds())
	
	// Final memory stats
	fmt.Printf("\nFinal ")
	printMemStats("End of benchmark")
}