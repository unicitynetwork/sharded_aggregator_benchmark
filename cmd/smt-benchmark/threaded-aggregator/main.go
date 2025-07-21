package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

// Constants for the benchmark
const (
	defaultCommitments   = 1
	defaultThreads       = 1
	batchSize            = 1000
	algorithmID          = "secp256k1"
	sha256Prefix         = "0000" // Algorithm prefix for SHA256
	aggregatorURL        = "https://goggregator-test.unicity.network"
)

// SubmitCommitmentRequest represents the JSON-RPC request to submit a commitment
type SubmitCommitmentRequest struct {
	RequestID              string        `json:"requestId"`
	TransactionHash        string        `json:"transactionHash"`
	Authenticator          Authenticator `json:"authenticator"`
	Receipt                *bool         `json:"receipt,omitempty"`
	AggregateRequestCount  string        `json:"aggregateRequestCount"`
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string                  `json:"jsonrpc"`
	Method  string                  `json:"method"`
	Params  SubmitCommitmentRequest `json:"params"`
	ID      int                     `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int             `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// InclusionProof represents the response from get_inclusion_proof
type InclusionProof struct {
	Authenticator   Authenticator   `json:"authenticator"`
	MerkleTreePath  MerkleTreePath  `json:"merkleTreePath"`
	TransactionHash string          `json:"transactionHash"`
}

// MerkleTreePath represents the merkle tree path in the proof
type MerkleTreePath struct {
	Root  string      `json:"root"`
	Steps []ProofStep `json:"steps"`
}

// ProofStep represents a single step in the merkle proof
type ProofStep struct {
	Branch  []string    `json:"branch"`
	Path    string      `json:"path"`
	Sibling interface{} `json:"sibling"`
}

// ThreadResult holds the benchmark results for a single thread
type ThreadResult struct {
	ThreadID               int
	NumCommitments         int
	GenerationTime         time.Duration
	SMTBuildTime           time.Duration
	RootCalculationTime    time.Duration
	AggregatorSubmitTime   time.Duration
	InclusionProofWaitTime time.Duration
	TotalTime              time.Duration
	RootHash               string
	SubmittedRequestID     string
	AggregatorResponse     string
	InclusionProof         *InclusionProof
	Error                  error
}

// AggregatedResults holds the combined results from all threads
type AggregatedResults struct {
	TotalCommitments       int
	TotalThreads           int
	TotalGenerationTime    time.Duration
	TotalSMTBuildTime      time.Duration
	TotalRootCalcTime      time.Duration
	TotalAggregatorTime    time.Duration
	TotalInclusionProofTime time.Duration
	WallClockTime          time.Duration
	ThreadResults          []ThreadResult
	AvgCommitsPerSec       float64
	TotalCommitsPerSec     float64
}

// Commitment represents a state transition commitment
type Commitment struct {
	RequestID       string
	TransactionHash string
	Authenticator   Authenticator
}

// Authenticator contains the cryptographic proof
type Authenticator struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	StateHash string `json:"stateHash"`
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
	
	// Generate random state data and create DataHash imprint
	stateData := make([]byte, 32)
	if _, err := rand.Read(stateData); err != nil {
		return nil, fmt.Errorf("failed to generate state data: %w", err)
	}
	stateHashImprint := createDataHashImprint(stateData)
	
	// Create request ID from public key and state hash imprint
	requestID, err := createRequestID(pubKeyBytes, stateHashImprint)
	if err != nil {
		return nil, fmt.Errorf("failed to create request ID: %w", err)
	}
	
	// Generate random transaction data and create DataHash imprint
	transactionData := make([]byte, 32)
	if _, err := rand.Read(transactionData); err != nil {
		return nil, fmt.Errorf("failed to generate transaction data: %w", err)
	}
	transactionHashImprint := createDataHashImprint(transactionData)
	
	// Extract transaction hash bytes for signing (skip algorithm prefix)
	txHashBytes, err := hex.DecodeString(transactionHashImprint[4:]) // Skip "0000" prefix
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction hash: %w", err)
	}
	
	// Sign the transaction hash bytes using compact format
	compactSig := ecdsa.SignCompact(privKey, txHashBytes, true) // true for compressed public key
	
	// Convert from btcec's [V || R || S] format to Unicity's [R || S || V] format
	sigBytesWithRecovery := convertBtcecToUnicity(compactSig)
	
	commitment := &Commitment{
		RequestID:       requestID,
		TransactionHash: transactionHashImprint,
		Authenticator: Authenticator{
			Algorithm: algorithmID,
			PublicKey: hex.EncodeToString(pubKeyBytes),
			Signature: hex.EncodeToString(sigBytesWithRecovery),
			StateHash: stateHashImprint,
		},
	}
	
	return commitment, nil
}

// calculateLeafValue calculates the SMT leaf value for a commitment
func calculateLeafValue(commitment *Commitment) ([]byte, error) {
	// Decode hex values for CBOR encoding
	pubKeyBytes, _ := hex.DecodeString(commitment.Authenticator.PublicKey)
	sigBytes, _ := hex.DecodeString(commitment.Authenticator.Signature)
	
	// CBOR encode the authenticator as array
	authenticatorArray := []interface{}{
		commitment.Authenticator.Algorithm,
		pubKeyBytes,
		sigBytes,
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

// getHostID generates a host ID from hostname
func getHostID() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return hostname
}

// convertBtcecToUnicity converts a signature from btcec's [V || R || S] format 
// to Unicity's [R || S || V] format
func convertBtcecToUnicity(compactSig []byte) []byte {
	// For compressed keys, btcec's V is 31-34. We normalize it to 0 or 1.
	v := compactSig[0] - 31
	r := compactSig[1:33]
	sigS := compactSig[33:65]

	signature := make([]byte, 65)
	copy(signature[0:32], r)
	copy(signature[32:64], sigS)
	signature[64] = v

	return signature
}

// createDataHashImprint creates a DataHash imprint in the Unicity format:
// 2 bytes algorithm (big-endian) + actual hash bytes
// For SHA256: algorithm = 0, so prefix is [0x00, 0x00]
func createDataHashImprint(data []byte) string {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)
	
	// Create imprint: algorithm (0x00, 0x00 for SHA256) + hash
	imprint := make([]byte, 2+len(hash))
	imprint[0] = 0x00 // SHA256 algorithm high byte
	imprint[1] = 0x00 // SHA256 algorithm low byte
	copy(imprint[2:], hash[:])
	
	return hex.EncodeToString(imprint)
}

// createRequestID creates a RequestID from public key and state hash imprint
func createRequestID(publicKey []byte, stateHashImprint string) (string, error) {
	// Decode the imprint to get the full bytes (algorithm + hash)
	stateHashBytes, err := hex.DecodeString(stateHashImprint)
	if err != nil {
		return "", fmt.Errorf("failed to decode state hash imprint: %w", err)
	}
	
	// Create the data to hash: publicKey + stateHashBytes (full imprint)
	data := make([]byte, 0, len(publicKey)+len(stateHashBytes))
	data = append(data, publicKey...)
	data = append(data, stateHashBytes...)
	
	// Hash and create request ID with algorithm prefix
	requestIDHash := sha256.Sum256(data)
	return fmt.Sprintf("0000%x", requestIDHash), nil
}

// submitToAggregator submits the tree root to the Unicity aggregator
func submitToAggregator(hostID string, threadID int, rootHash []byte, numCommitments int, privKey *btcec.PrivateKey) (string, string, error) {
	// Generate timestamp
	timestamp := time.Now().UnixNano()
	
	// Create state data from host ID, thread ID, and timestamp
	stateData := []byte(fmt.Sprintf("%s-%d-%d", hostID, threadID, timestamp))
	stateHashImprint := createDataHashImprint(stateData)
	
	// Create request ID from public key and state hash
	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	
	requestID, err := createRequestID(pubKeyBytes, stateHashImprint)
	if err != nil {
		return "", "", fmt.Errorf("failed to create request ID: %w", err)
	}
	
	// Create transaction hash imprint from root hash
	transactionHashImprint := createDataHashImprint(rootHash)
	
	// Extract just the hash bytes (skip algorithm prefix) for signing
	txHashBytes, err := hex.DecodeString(transactionHashImprint[4:]) // Skip "0000" prefix
	if err != nil {
		return "", requestID, fmt.Errorf("failed to decode transaction hash: %w", err)
	}
	
	// Sign the transaction hash bytes using compact format
	compactSig := ecdsa.SignCompact(privKey, txHashBytes, true) // true for compressed public key
	
	// Convert from btcec's [V || R || S] format to Unicity's [R || S || V] format
	sigBytesWithRecovery := convertBtcecToUnicity(compactSig)
	
	// Create the submission request
	receipt := true
	submitReq := SubmitCommitmentRequest{
		RequestID:       requestID,
		TransactionHash: transactionHashImprint,
		Authenticator: Authenticator{
			Algorithm: algorithmID,
			PublicKey: hex.EncodeToString(pubKeyBytes),
			Signature: hex.EncodeToString(sigBytesWithRecovery),
			StateHash: stateHashImprint,
		},
		Receipt:               &receipt,
		AggregateRequestCount: strconv.Itoa(numCommitments),
	}
	
	// Create JSON-RPC request
	rpcReq := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "submit_commitment",
		Params:  submitReq,
		ID:      threadID,
	}
	
	// Marshal to JSON
	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", requestID, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequest("POST", aggregatorURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", requestID, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", requestID, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response body first to debug
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", requestID, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Try to parse as JSON-RPC response
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		// If it fails, log the actual response for debugging
		return "", requestID, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}
	
	// Check for JSON-RPC error
	if rpcResp.Error != nil {
		return "", requestID, fmt.Errorf("JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	
	return string(rpcResp.Result), requestID, nil
}

// getInclusionProof retrieves the inclusion proof for a given request ID
func getInclusionProof(requestID string, threadID int) (*InclusionProof, error) {
	// Create JSON-RPC request
	params := map[string]string{"requestId": requestID}
	
	rpcReq := struct {
		JSONRPC string            `json:"jsonrpc"`
		Method  string            `json:"method"`
		Params  map[string]string `json:"params"`
		ID      int               `json:"id"`
	}{
		JSONRPC: "2.0",
		Method:  "get_inclusion_proof",
		Params:  params,
		ID:      threadID,
	}
	
	// Marshal to JSON
	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequest("POST", aggregatorURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response body first
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	
	// Try to parse as JSON-RPC response
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}
	
	// Check for JSON-RPC error
	if rpcResp.Error != nil {
		// Error code -32002 typically means not found/not ready yet
		if rpcResp.Error.Code == -32002 {
			return nil, fmt.Errorf("not found")
		}
		return nil, fmt.Errorf("JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	
	// Parse the result
	var proof InclusionProof
	if err := json.Unmarshal(rpcResp.Result, &proof); err != nil {
		return nil, fmt.Errorf("failed to parse inclusion proof: %w", err)
	}
	
	return &proof, nil
}

// waitForInclusionProof polls for the inclusion proof with retries
func waitForInclusionProof(requestID string, threadID int, maxWaitTime time.Duration) (*InclusionProof, time.Duration, error) {
	startTime := time.Now()
	endTime := startTime.Add(maxWaitTime)
	
	// Initial delay to allow aggregator to process
	time.Sleep(100 * time.Millisecond)
	
	retryCount := 0
	for time.Now().Before(endTime) {
		proof, err := getInclusionProof(requestID, threadID)
		if err == nil && proof != nil {
			waitTime := time.Since(startTime)
			return proof, waitTime, nil
		}
		
		// If error is not "not found", it's a real error
		if err != nil && !strings.Contains(err.Error(), "not found") {
			return nil, time.Since(startTime), err
		}
		
		retryCount++
		// Exponential backoff with max 5 seconds
		backoff := time.Duration(math.Min(float64(100*math.Pow(2, float64(retryCount))), 5000)) * time.Millisecond
		time.Sleep(backoff)
	}
	
	return nil, maxWaitTime, fmt.Errorf("timeout waiting for inclusion proof after %v", maxWaitTime)
}

// runThreadBenchmark runs the benchmark for a single thread
func runThreadBenchmark(threadID, numCommitments int, submitToAgg bool, wg *sync.WaitGroup, results chan<- ThreadResult) {
	defer wg.Done()
	
	result := ThreadResult{
		ThreadID:       threadID,
		NumCommitments: numCommitments,
	}
	
	startTotal := time.Now()
	
	// Generate a key pair for aggregator submission
	aggregatorPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		result.Error = fmt.Errorf("thread %d: failed to generate aggregator key: %w", threadID, err)
		results <- result
		return
	}
	
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
	
	// Phase 4: Submit to aggregator (if enabled)
	if submitToAgg {
		startAgg := time.Now()
		
		hostID := getHostID()
		response, requestID, err := submitToAggregator(hostID, threadID, root, numCommitments, aggregatorPrivKey)
		if err != nil {
			result.AggregatorResponse = fmt.Sprintf("Submit Error: %v", err)
			result.AggregatorSubmitTime = time.Since(startAgg)
		} else {
			result.AggregatorResponse = "Submit Success: " + response
			result.SubmittedRequestID = requestID
			result.AggregatorSubmitTime = time.Since(startAgg)
			
			// Phase 5: Wait for inclusion proof
			fmt.Printf("Thread %d: Waiting for inclusion proof for request %s...\n", threadID, requestID[:16]+"...")
			fmt.Printf("Thread %d: Debug - Full Request ID: %s\n", threadID, requestID)
			fmt.Printf("Thread %d: Debug - Root Hash (Transaction): %s\n", threadID, result.RootHash)
			
			proof, waitTime, err := waitForInclusionProof(requestID, threadID, 30*time.Second)
			if err != nil {
				fmt.Printf("Thread %d: Failed to get inclusion proof: %v\n", threadID, err)
				result.AggregatorResponse += fmt.Sprintf(" | Proof Error: %v", err)
			} else {
				result.InclusionProof = proof
				result.InclusionProofWaitTime = waitTime
				fmt.Printf("Thread %d: Got inclusion proof after %v\n", threadID, waitTime)
				// Debug: print what we got back
				if proof.TransactionHash != "" {
					fmt.Printf("Thread %d: Debug - Proof Transaction Hash: %s\n", threadID, proof.TransactionHash)
				}
			}
		}
	}
	
	result.TotalTime = time.Since(startTotal)
	
	results <- result
}

func parseArgs() (int, int, bool) {
	var numCommitments, numThreads int
	var submitToAgg bool
	
	// Define flags
	flag.IntVar(&numCommitments, "n", defaultCommitments, "Number of commitments to generate per thread")
	flag.IntVar(&numCommitments, "count", defaultCommitments, "Number of commitments to generate per thread")
	flag.IntVar(&numThreads, "t", defaultThreads, "Number of threads to run")
	flag.IntVar(&numThreads, "threads", defaultThreads, "Number of threads to run")
	flag.BoolVar(&submitToAgg, "submit", false, "Submit tree roots to Unicity aggregator")
	flag.BoolVar(&submitToAgg, "s", false, "Submit tree roots to Unicity aggregator (short)")
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
	
	return numCommitments, numThreads, submitToAgg
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [commitments_per_thread] [thread_count]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fmt.Fprintf(os.Stderr, "  -n, --count     Number of commitments per thread (default: %d)\n", defaultCommitments)
	fmt.Fprintf(os.Stderr, "  -t, --threads   Number of threads (default: %d)\n", defaultThreads)
	fmt.Fprintf(os.Stderr, "  -s, --submit    Submit tree roots to Unicity aggregator\n")
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  %s                    # 1 commitment, 1 thread\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s 1000               # 1000 commitments, 1 thread\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s 1000 4             # 1000 commitments per thread, 4 threads\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s -n 1000 -t 8 -s    # 1000 per thread, 8 threads, submit to aggregator\n", os.Args[0])
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
			agg.TotalAggregatorTime += r.AggregatorSubmitTime
			agg.TotalInclusionProofTime += r.InclusionProofWaitTime
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
	numCommitments, numThreads, submitToAgg := parseArgs()
	
	// Set GOMAXPROCS to use all available CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// Run garbage collection before benchmark
	runtime.GC()
	
	fmt.Printf("Multi-threaded SMT Benchmark with Aggregator Integration\n")
	fmt.Printf("========================================================\n")
	fmt.Printf("Threads: %d\n", numThreads)
	fmt.Printf("Commitments per thread: %d\n", numCommitments)
	fmt.Printf("Total commitments: %d\n", numCommitments*numThreads)
	fmt.Printf("CPU cores available: %d\n", runtime.NumCPU())
	fmt.Printf("Submit to aggregator: %v\n", submitToAgg)
	if submitToAgg {
		fmt.Printf("Aggregator URL: %s\n", aggregatorURL)
		fmt.Printf("Host ID: %s\n", getHostID())
	}
	fmt.Printf("========================================================\n\n")
	
	// Create channels and wait group
	var wg sync.WaitGroup
	results := make(chan ThreadResult, numThreads)
	
	// Record start time
	startTime := time.Now()
	
	// Launch threads
	fmt.Printf("Launching %d threads...\n", numThreads)
	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go runThreadBenchmark(i, numCommitments, submitToAgg, &wg, results)
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
			if submitToAgg && result.AggregatorResponse != "" {
				fmt.Printf("  Aggregator: %s\n", result.AggregatorResponse)
			}
		}
	}
	
	wallClockTime := time.Since(startTime)
	
	// Print memory stats
	fmt.Println()
	printMemStats("After all threads completed")
	
	// Aggregate results
	fmt.Printf("\n========================================================\n")
	fmt.Printf("Per-Thread Results:\n")
	fmt.Printf("========================================================\n")
	
	for _, r := range threadResults {
		if r.Error == nil {
			fmt.Printf("Thread %d:\n", r.ThreadID)
			fmt.Printf("  Commitments: %d\n", r.NumCommitments)
			fmt.Printf("  Generation: %v (%.2f commits/sec)\n", 
				r.GenerationTime, float64(r.NumCommitments)/r.GenerationTime.Seconds())
			fmt.Printf("  SMT Build: %v (%.2f leaves/sec)\n", 
				r.SMTBuildTime, float64(r.NumCommitments)/r.SMTBuildTime.Seconds())
			fmt.Printf("  Root Calc: %v\n", r.RootCalculationTime)
			if submitToAgg {
				fmt.Printf("  Aggregator Submit: %v\n", r.AggregatorSubmitTime)
				if r.InclusionProof != nil {
					fmt.Printf("  Inclusion Proof Wait: %v\n", r.InclusionProofWaitTime)
					fmt.Printf("  Inclusion Proof Details:\n")
					fmt.Printf("    Merkle Root: %s\n", r.InclusionProof.MerkleTreePath.Root)
					fmt.Printf("    Proof Steps: %d\n", len(r.InclusionProof.MerkleTreePath.Steps))
					fmt.Printf("    Transaction Hash: %s\n", r.InclusionProof.TransactionHash)
				}
			}
			fmt.Printf("  Total: %v\n", r.TotalTime)
			fmt.Printf("  Root Hash: %s\n", r.RootHash)
			fmt.Println()
		}
	}
	
	// Print aggregated results
	agg := aggregateResults(threadResults, wallClockTime)
	
	fmt.Printf("========================================================\n")
	fmt.Printf("Aggregated Results:\n")
	fmt.Printf("========================================================\n")
	fmt.Printf("Total threads: %d (successful: %d)\n", numThreads, agg.TotalThreads)
	fmt.Printf("Total commitments: %d\n", agg.TotalCommitments)
	fmt.Printf("Wall clock time: %v\n", agg.WallClockTime)
	fmt.Printf("\nCumulative thread time:\n")
	fmt.Printf("  Generation: %v\n", agg.TotalGenerationTime)
	fmt.Printf("  SMT Build: %v\n", agg.TotalSMTBuildTime)
	fmt.Printf("  Root Calc: %v\n", agg.TotalRootCalcTime)
	if submitToAgg {
		fmt.Printf("  Aggregator Submit: %v\n", agg.TotalAggregatorTime)
		fmt.Printf("  Inclusion Proof Wait: %v\n", agg.TotalInclusionProofTime)
	}
	fmt.Printf("\nThroughput:\n")
	fmt.Printf("  Average per thread: %.2f commits/sec\n", agg.AvgCommitsPerSec)
	fmt.Printf("  Total (parallel): %.2f commits/sec\n", agg.TotalCommitsPerSec)
	fmt.Printf("  Speedup: %.2fx\n", agg.TotalCommitsPerSec/(agg.AvgCommitsPerSec/float64(agg.TotalThreads)))
	
	// Final memory stats
	fmt.Printf("\nFinal ")
	printMemStats("End of benchmark")
}