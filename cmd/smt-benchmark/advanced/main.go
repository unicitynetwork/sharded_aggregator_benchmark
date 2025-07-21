package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/aggregator-go/internal/models"
	"github.com/unicitynetwork/aggregator-go/internal/smt"
	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// Constants for the benchmark
const (
	numCommitments = 100000
	batchSize      = 1000
	algorithmID    = "secp256k1"
)

// BenchmarkResult holds timing information
type BenchmarkResult struct {
	GenerationTime     time.Duration
	SMTBuildTime       time.Duration
	RootCalculationTime time.Duration
	TotalTime          time.Duration
	CommitmentsPerSec  float64
	LeavesPerSec       float64
}

// generateValidCommitment generates a cryptographically valid commitment
func generateValidCommitment(index int) (*models.Commitment, error) {
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
	
	// Create state hash with algorithm imprint
	stateHash, err := api.NewStateHashFromBytes(stateHashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create state hash: %w", err)
	}
	
	// Calculate request ID: SHA256(publicKey || stateHashImprint)
	requestIDHasher := sha256.New()
	requestIDHasher.Write(pubKeyBytes)
	requestIDHasher.Write([]byte(stateHash))
	requestIDBytes := requestIDHasher.Sum(nil)
	
	requestID, err := api.NewRequestIDFromBytes(requestIDBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create request ID: %w", err)
	}
	
	// Generate random transaction hash (32 bytes)
	txHashBytes := make([]byte, 32)
	if _, err := rand.Read(txHashBytes); err != nil {
		return nil, fmt.Errorf("failed to generate transaction hash: %w", err)
	}
	
	transactionHash, err := api.NewTransactionHashFromBytes(txHashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction hash: %w", err)
	}
	
	// Sign the transaction hash (without prefix)
	signature := ecdsa.Sign(privKey, txHashBytes)
	
	// Convert signature to 65-byte format (R || S || V)
	sigBytes := signature.Serialize()
	// Add recovery ID as the 65th byte (simplified, using 0)
	sigBytesWithRecovery := append(sigBytes, 0)
	
	commitment := &models.Commitment{
		RequestID:       requestID,
		TransactionHash: transactionHash,
		Authenticator: models.Authenticator{
			Algorithm: algorithmID,
			PublicKey: api.HexBytes(pubKeyBytes),
			Signature: api.HexBytes(sigBytesWithRecovery),
			StateHash: stateHash,
		},
	}
	
	return commitment, nil
}

// calculateLeafValue calculates the SMT leaf value for a commitment
func calculateLeafValue(commitment *models.Commitment) (api.HexBytes, error) {
	// CBOR encode the authenticator as array
	authenticatorArray := []interface{}{
		commitment.Authenticator.Algorithm,
		commitment.Authenticator.PublicKey,
		commitment.Authenticator.Signature,
		string(commitment.Authenticator.StateHash),
	}
	
	authenticatorCBOR, err := cbor.Marshal(authenticatorArray)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR encode authenticator: %w", err)
	}
	
	// Calculate leaf value: SHA256(authenticatorCBOR || transactionHashImprint)
	leafHasher := sha256.New()
	leafHasher.Write(authenticatorCBOR)
	leafHasher.Write([]byte(commitment.TransactionHash))
	leafHashBytes := leafHasher.Sum(nil)
	
	// Create leaf value with algorithm imprint
	leafValue, err := api.NewHexBytesFromBytesWithPrefix(leafHashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf value: %w", err)
	}
	
	return leafValue, nil
}

func runBenchmark() (*BenchmarkResult, error) {
	result := &BenchmarkResult{}
	startTotal := time.Now()
	
	fmt.Printf("SMT Benchmark: Generating and inserting %d commitments\n", numCommitments)
	fmt.Println("================================================")
	
	// Phase 1: Generate commitments
	fmt.Printf("\nPhase 1: Generating %d valid commitments...\n", numCommitments)
	startGen := time.Now()
	
	commitments := make([]*models.Commitment, numCommitments)
	leaves := make([]smt.Leaf, numCommitments)
	
	for i := 0; i < numCommitments; i++ {
		commitment, err := generateValidCommitment(i)
		if err != nil {
			return nil, fmt.Errorf("failed to generate commitment %d: %w", i, err)
		}
		
		leafValue, err := calculateLeafValue(commitment)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate leaf value %d: %w", i, err)
		}
		
		commitments[i] = commitment
		leaves[i] = smt.Leaf{
			Path:  commitment.RequestID.GetPath(),
			Value: leafValue,
		}
		
		if (i+1)%10000 == 0 {
			fmt.Printf("  Generated %d commitments...\n", i+1)
		}
	}
	
	result.GenerationTime = time.Since(startGen)
	fmt.Printf("✓ Generated %d commitments in %v\n", numCommitments, result.GenerationTime)
	fmt.Printf("  Average time per commitment: %v\n", result.GenerationTime/time.Duration(numCommitments))
	
	// Print memory stats
	printMemStats("After generation")
	
	// Phase 2: Create SMT and add all leaves
	fmt.Printf("\nPhase 2: Building Sparse Merkle Tree...\n")
	
	// Create a new SMT
	tree := smt.NewSparseMerkleTree()
	
	startSMT := time.Now()
	
	// Add leaves in batches for more realistic performance
	for i := 0; i < numCommitments; i += batchSize {
		end := i + batchSize
		if end > numCommitments {
			end = numCommitments
		}
		
		batch := leaves[i:end]
		
		// Add batch to tree
		for _, leaf := range batch {
			tree.AddLeaf(leaf.Path, leaf.Value)
		}
		
		if (i+batchSize)%10000 == 0 {
			fmt.Printf("  Added %d leaves to SMT...\n", i+batchSize)
		}
	}
	
	result.SMTBuildTime = time.Since(startSMT)
	fmt.Printf("✓ Built SMT with %d leaves in %v\n", numCommitments, result.SMTBuildTime)
	fmt.Printf("  Average time per leaf: %v\n", result.SMTBuildTime/time.Duration(numCommitments))
	
	// Print memory stats
	printMemStats("After SMT build")
	
	// Phase 3: Calculate root hash
	fmt.Printf("\nPhase 3: Calculating root hash...\n")
	startRoot := time.Now()
	
	root := tree.Root()
	
	result.RootCalculationTime = time.Since(startRoot)
	fmt.Printf("✓ Calculated root hash in %v\n", result.RootCalculationTime)
	fmt.Printf("  Root hash: %s\n", root)
	
	// Verify we can get inclusion proofs
	fmt.Printf("\nPhase 4: Verifying inclusion proofs...\n")
	
	// Test getting proof for first, middle, and last commitment
	testIndices := []int{0, numCommitments / 2, numCommitments - 1}
	for _, idx := range testIndices {
		path := commitments[idx].RequestID.GetPath()
		proof, err := tree.GetInclusionProof(path)
		if err != nil {
			return nil, fmt.Errorf("failed to get inclusion proof for commitment %d: %w", idx, err)
		}
		fmt.Printf("  ✓ Got inclusion proof for commitment %d (path: %s, steps: %d)\n", 
			idx, path[:16]+"...", len(proof.Steps))
	}
	
	// Calculate final metrics
	result.TotalTime = time.Since(startTotal)
	result.CommitmentsPerSec = float64(numCommitments) / result.GenerationTime.Seconds()
	result.LeavesPerSec = float64(numCommitments) / result.SMTBuildTime.Seconds()
	
	return result, nil
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

func main() {
	// Run garbage collection before benchmark
	runtime.GC()
	
	// Run the benchmark
	result, err := runBenchmark()
	if err != nil {
		log.Fatalf("Benchmark failed: %v", err)
	}
	
	// Print summary
	fmt.Printf("\n================================================\n")
	fmt.Printf("Benchmark Summary:\n")
	fmt.Printf("  Total commitments: %d\n", numCommitments)
	fmt.Printf("  Generation time: %v (%.2f commits/sec)\n", 
		result.GenerationTime, result.CommitmentsPerSec)
	fmt.Printf("  SMT build time: %v (%.2f leaves/sec)\n", 
		result.SMTBuildTime, result.LeavesPerSec)
	fmt.Printf("  Root calculation: %v\n", result.RootCalculationTime)
	fmt.Printf("  Total time: %v\n", result.TotalTime)
	fmt.Printf("  Total throughput: %.2f commits/sec\n", 
		float64(numCommitments)/result.TotalTime.Seconds())
	
	// Print final memory stats
	fmt.Printf("\nFinal ")
	printMemStats("End of benchmark")
}

// Helper function to resolve import paths
func init() {
	// This helps with import resolution when running from different directories
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	fmt.Printf("Running from: %s\n", dir)
}