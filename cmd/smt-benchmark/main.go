package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

// Constants for the benchmark
const (
	defaultCommitments = 1
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

// SparseMerkleTree represents a simple SMT implementation
type SparseMerkleTree struct {
	leaves map[string][]byte // path -> value
	root   []byte
}

// NewSparseMerkleTree creates a new SMT
func NewSparseMerkleTree() *SparseMerkleTree {
	return &SparseMerkleTree{
		leaves: make(map[string][]byte),
	}
}

// AddLeaf adds a single leaf to the tree
func (smt *SparseMerkleTree) AddLeaf(path string, value []byte) {
	smt.leaves[path] = value
}

// AddLeaves adds multiple leaves to the tree
func (smt *SparseMerkleTree) AddLeaves(leaves map[string][]byte) {
	for path, value := range leaves {
		smt.leaves[path] = value
	}
}

// CalculateRoot calculates the root hash of the tree
func (smt *SparseMerkleTree) CalculateRoot() []byte {
	// Simplified root calculation for benchmark
	h := sha256.New()
	for path, value := range smt.leaves {
		h.Write([]byte(path))
		h.Write(value)
	}
	return h.Sum(nil)
}

// generateValidCommitment generates a cryptographically valid commitment
func generateValidCommitment(index int) (*Commitment, *btcec.PrivateKey, error) {
	// Generate a new secp256k1 key pair
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	
	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	
	// Generate random state hash (32 bytes)
	stateHashBytes := make([]byte, 32)
	if _, err := rand.Read(stateHashBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to generate state hash: %w", err)
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
		return nil, nil, fmt.Errorf("failed to generate transaction hash: %w", err)
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
	
	return commitment, privKey, nil
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
	
	// Add algorithm prefix
	leafValue := sha256Prefix + hex.EncodeToString(leafHash)
	return []byte(leafValue), nil
}

// getPath converts request ID to SMT path by prefixing with 0x01
func getPath(requestID string) string {
	return "01" + requestID
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
	
	fmt.Printf("SMT Benchmark: Generating and inserting %d commitments\n", numCommitments)
	fmt.Println("================================================")
	
	// Phase 1: Generate commitments
	fmt.Printf("\nPhase 1: Generating %d valid commitments...\n", numCommitments)
	startGen := time.Now()
	
	commitments := make([]*Commitment, numCommitments)
	leaves := make(map[string][]byte)
	
	for i := 0; i < numCommitments; i++ {
		commitment, _, err := generateValidCommitment(i)
		if err != nil {
			log.Fatalf("Failed to generate commitment %d: %v", i, err)
		}
		
		leafValue, err := calculateLeafValue(commitment)
		if err != nil {
			log.Fatalf("Failed to calculate leaf value %d: %v", i, err)
		}
		
		commitments[i] = commitment
		path := getPath(commitment.RequestID)
		leaves[path] = leafValue
		
		if (i+1)%10000 == 0 {
			fmt.Printf("  Generated %d commitments...\n", i+1)
		}
	}
	
	genDuration := time.Since(startGen)
	fmt.Printf("✓ Generated %d commitments in %v\n", numCommitments, genDuration)
	fmt.Printf("  Average time per commitment: %v\n", genDuration/time.Duration(numCommitments))
	
	// Phase 2: Create SMT and add all leaves
	fmt.Printf("\nPhase 2: Building Sparse Merkle Tree...\n")
	smt := NewSparseMerkleTree()
	
	startSMT := time.Now()
	
	// Add leaves in batches for more realistic performance
	batchSize := 1000
	if numCommitments < batchSize {
		batchSize = numCommitments
	}
	
	for i := 0; i < numCommitments; i += batchSize {
		end := i + batchSize
		if end > numCommitments {
			end = numCommitments
		}
		
		batch := make(map[string][]byte)
		for j := i; j < end; j++ {
			path := getPath(commitments[j].RequestID)
			batch[path] = leaves[path]
		}
		
		smt.AddLeaves(batch)
		
		if (i+batchSize)%10000 == 0 {
			fmt.Printf("  Added %d leaves to SMT...\n", i+batchSize)
		}
	}
	
	smtDuration := time.Since(startSMT)
	fmt.Printf("✓ Built SMT with %d leaves in %v\n", numCommitments, smtDuration)
	fmt.Printf("  Average time per leaf: %v\n", smtDuration/time.Duration(numCommitments))
	
	// Phase 3: Calculate root hash
	fmt.Printf("\nPhase 3: Calculating root hash...\n")
	startRoot := time.Now()
	
	root := smt.CalculateRoot()
	
	rootDuration := time.Since(startRoot)
	fmt.Printf("✓ Calculated root hash in %v\n", rootDuration)
	fmt.Printf("  Root hash: %x\n", root)
	
	// Summary
	totalDuration := time.Since(startGen)
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
}