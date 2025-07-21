module github.com/vrogojin/multi-aggregator-sim

go 1.24

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	github.com/fxamacker/cbor/v2 v2.7.0
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

// For using the reference implementation's packages
replace github.com/unicitynetwork/aggregator-go => ./refmaterials/aggregator-go