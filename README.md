# Go KMS Signer for Ethereum

[![Go Reference](https://pkg.go.dev/badge/github.com/courtyard-nft/go-kms-signer.svg)](https://pkg.go.dev/github.com/courtyard-nft/go-kms-signer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This Go module provides an implementation of the `go-ethereum` `bind.SignerFn` interface using Google Cloud Key Management Service (KMS).
It allows you to sign Ethereum transactions using keys stored securely in GCP KMS.

## Features

*   Signs Ethereum transactions using ECDSA keys (specifically `secp256k1` curve) stored in GCP KMS.
*   Automatically fetches the public key and derives the Ethereum address.
*   Handles conversion between KMS's DER signature format and Ethereum's `[R || S || V]` format.
*   Calculates the correct recovery ID (V) for signatures.
*   Provides a `bind.SignerFn` compatible function for easy integration with `go-ethereum` contract bindings.
*   Implements EIP-155 replay protection.
*   Includes exponential backoff for KMS signing operations.
*   Caches the public key and address for efficiency.

## Prerequisites

*   Go 1.18 or later.
*   A Google Cloud Platform project with the KMS API enabled.
*   A KMS key ring and an asymmetric signing key (purpose: `ASYMMETRIC_SIGN`, algorithm: `EC_SIGN_SECP256K1_SHA256`).
*   Appropriate GCP credentials configured for your environment (e.g., via `gcloud auth application-default login`, service account key file, or Workload Identity).

## Installation

```bash
# Replace courtyard-nft with the actual path where this module will live
go get github.com/courtyard-nft/go-kms-signer
```

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/common"
	// Replace with the actual import path
	kms "github.com/courtyard-nft/go-kms-signer"
)

func main() {
	ctx := context.Background()

	// Replace with your KMS key resource name
	keyName := "projects/your-gcp-project/locations/global/keyRings/your-keyring/cryptoKeys/your-eth-key/cryptoKeyVersions/1"

	config := kms.KMSSignerConfig{
		KeyName: keyName,
	}

	// Create a new KMS Signer
	signer, err := kms.NewKMSSigner(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create KMS signer: %v", err)
	}
	defer signer.Close() // Close the client when done

	fmt.Printf("Using signer address: %s\n", signer.Address().Hex())

	// Example: Create and sign a dummy transaction
	chainID := big.NewInt(1) // Example: Mainnet chain ID
	toAddress := common.HexToAddress("0xRecipientAddress")
	amount := big.NewInt(10000000000000000) // 0.01 ETH
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(50000000000) // 50 Gwei
	nonce := uint64(0)                  // Get nonce from network

	tx := types.NewTransaction(nonce, toAddress, amount, gasLimit, gasPrice, nil)

	// Get the SignerFn
	signerFn := signer.SignerFn(chainID)

	// Sign the transaction
	signedTx, err := signerFn(signer.Address(), tx)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	fmt.Printf("Transaction signed successfully! Hash: %s\n", signedTx.Hash().Hex())

	// Now you can send the signedTx using an Ethereum client
	// client.SendTransaction(ctx, signedTx)
}

```

## Key Considerations

*   **Hashing:** This library expects the **message hash** to be passed to the `Sign` method. For standard Ethereum transactions, `go-ethereum`'s `Signer` implementations (like `types.NewEIP155Signer`) calculate the correct transaction hash. Ensure you provide the 32-byte Keccak256 hash when using the `Sign` method directly.
*   **KMS Key Algorithm:** Ensure your KMS key uses the `EC_SIGN_SECP256K1_SHA256` algorithm. While KMS might support other ECDSA curves, Ethereum requires `secp256k1`.
*   **Permissions:** The service account or credentials used need the `cloudkms.cryptoKeyVersions.useToSign` IAM permission on the specific key version and `cloudkms.cryptoKeyVersions.getPublicKey` permission.
*   **Error Handling:** The `Sign` method includes retries with exponential backoff for transient KMS errors. Inspect returned errors for potential non-transient issues.
*   **Context:** Pass appropriate `context.Context` objects to `NewKMSSigner` and `Sign` for timeout and cancellation control.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details. 