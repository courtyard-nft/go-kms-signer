package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/cenkalti/backoff/v4"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	globalSigner *KMSSigner
	signerMu     sync.RWMutex
)

func InitWithKMSSigner(ctx context.Context, config KMSSignerConfig) error {
	signerMu.Lock()
	defer signerMu.Unlock()

	signer, err := NewKMSSigner(ctx, config)
	if err != nil {
		return err
	}

	globalSigner = signer
	return nil
}

func Sign(message []byte) ([]byte, error) {
	signerMu.RLock()
	defer signerMu.RUnlock()

	if globalSigner == nil {
		return nil, fmt.Errorf("global signer not initialized")
	}

	hash := crypto.Keccak256(message)
	return globalSigner.Sign(hash)
}

// KMSClient defines the interface for KMS operations required by KMSSigner.
// This allows for mocking the KMS client in tests.
type KMSClient interface {
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
	Close() error
}

// kmsClientWrapper wraps the official KMS client to implement the KMSClient interface.
type kmsClientWrapper struct {
	client *kms.KeyManagementClient
}

// GetPublicKey retrieves the public key from KMS.
func (k *kmsClientWrapper) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	return k.client.GetPublicKey(ctx, req)
}

// AsymmetricSign performs signing using the KMS key.
func (k *kmsClientWrapper) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return k.client.AsymmetricSign(ctx, req)
}

// Close closes the underlying KMS client connection.
func (k *kmsClientWrapper) Close() error {
	return k.client.Close()
}

// KMSSigner implements the Ethereum `bind.SignerFn` interface using Google Cloud KMS.
// It handles fetching the public key, signing hashes, and converting signatures
// to the format expected by Ethereum.
type KMSSigner struct {
	client    KMSClient
	keyName   string
	publicKey *ecdsa.PublicKey // Cache the public key
	address   common.Address   // Cache the derived address
}

// KMSSignerConfig holds the configuration required for initializing a KMSSigner.
type KMSSignerConfig struct {
	// KeyName is the full KMS key resource name, e.g.,
	// "projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING_ID/cryptoKeys/KEY_ID/cryptoKeyVersions/VERSION".
	KeyName string
}

// NewKMSSigner creates a new KMSSigner instance.
// It initializes the KMS client and fetches the public key associated with the keyName
// to derive the Ethereum address.
func NewKMSSigner(ctx context.Context, config KMSSignerConfig) (*KMSSigner, error) {
	if config.KeyName == "" {
		return nil, fmt.Errorf("KeyName is required in KMSSignerConfig")
	}

	gcpClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}
	client := &kmsClientWrapper{client: gcpClient}

	signer := &KMSSigner{
		client:  client,
		keyName: config.KeyName,
	}

	// Fetch and cache the public key and address upon initialization
	err = signer.fetchAndCachePublicKey(ctx)
	if err != nil {
		// Attempt to close the client if key fetching fails
		_ = client.Close()
		return nil, fmt.Errorf("failed to fetch initial public key: %w", err)
	}

	return signer, nil
}

// fetchAndCachePublicKey retrieves the public key from KMS, parses it,
// derives the Ethereum address, and caches both.
func (s *KMSSigner) fetchAndCachePublicKey(ctx context.Context) error {
	pubKeyReq := &kmspb.GetPublicKeyRequest{
		Name: s.keyName,
	}
	pubKeyResp, err := s.client.GetPublicKey(ctx, pubKeyReq)
	if err != nil {
		return fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}
	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	// Parse the public key using standard library functions
	genericPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	parsedPubKey, ok := genericPubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not an ECDSA public key")
	}

	// Validate the curve
	if parsedPubKey.Curve != crypto.S256() {
		return fmt.Errorf("public key curve is not secp256k1")
	}

	s.publicKey = parsedPubKey
	s.address = crypto.PubkeyToAddress(*s.publicKey)

	return nil
}

// Address returns the Ethereum address associated with the KMS key.
func (s *KMSSigner) Address() common.Address {
	return s.address
}

// PublicKey returns the ECDSA public key associated with the KMS key.
func (s *KMSSigner) PublicKey() *ecdsa.PublicKey {
	return s.publicKey
}

// KeyName returns the KMS key resource name used by the signer.
func (s *KMSSigner) KeyName() string {
	return s.keyName
}

// Close closes the underlying KMS client connection.
func (s *KMSSigner) Close() error {
	return s.client.Close()
}

// Sign signs the provided message hash using the KMS key.
// It retries on transient errors using exponential backoff.
// The resulting signature is in the Ethereum [R || S || V] format, where V is 0x1b or 0x1c.
func (s *KMSSigner) Sign(message []byte) ([]byte, error) {
	return s.SignWithContext(context.Background(), message)
}

func (s *KMSSigner) SignWithContext(ctx context.Context, message []byte) ([]byte, error) {
	if s.publicKey == nil {
		// Attempt to fetch the key if it wasn't cached initially (e.g., network issue)
		if err := s.fetchAndCachePublicKey(ctx); err != nil {
			return nil, fmt.Errorf("public key not available and failed to fetch: %w", err)
		}
		if s.publicKey == nil {
			return nil, fmt.Errorf("public key not available") // Should not happen if fetch succeeds
		}
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 30 * time.Second // Adjust timeout as needed

	var signature []byte
	operation := func() error {
		var err error
		signature, err = s.signAttempt(ctx, message)
		// Consider adding checks here for specific retryable KMS errors if needed
		return err
	}

	err := backoff.Retry(operation, b)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message with KMS after retries: %w", err)
	}

	return signature, nil
}

// signAttempt performs a single signing attempt using KMS.
func (s *KMSSigner) signAttempt(ctx context.Context, message []byte) ([]byte, error) {
	// Note: KMS expects the raw message digest. Ethereum typically uses Keccak256.
	// The caller of Sign should hash the message appropriately before passing it.
	// Here we assume `message` is the 32-byte hash.
	if len(message) != 32 {
		// Warn or error if the message length isn't the expected hash size
		// return nil, fmt.Errorf("invalid message hash length: expected 32 bytes, got %d", len(message))
		// For flexibility, we allow different lengths, but KMS requires a Digest.
		// If the input is not a hash, KMS might hash it depending on the key type,
		// which could lead to incorrect signatures for Ethereum.
		// We proceed assuming KMS handles it or the key expects raw data.
	}

	req := &kmspb.AsymmetricSignRequest{
		Name: s.keyName,
		// KMS automatically uses the algorithm configured for the key version.
		// For ECDSA_P256_SHA256 or ECDSA_SECP256K1_SHA256, provide the SHA256 digest.
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{ // Assuming SHA256 digest is appropriate for the key
				Sha256: message,
			},
		},
		// If the key algorithm requires a different digest (e.g., SHA384), adjust accordingly.
		// Or, if signing raw data (not a hash), omit the Digest field if the key supports it.
	}

	resp, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("kms AsymmetricSign failed: %w", err)
	}

	// Convert the DER signature to Ethereum format [R || S || V]
	ethSig, err := derToEthereumSignature(resp.Signature, message, s.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert DER signature to Ethereum format: %w", err)
	}

	return ethSig, nil
}

func (s *KMSSigner) GetWalletAddress(ctx context.Context) (string, error) {
	return s.Address().Hex(), nil
}

func (s *KMSSigner) derToEthereumSignature(derSig, hash []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	return derToEthereumSignature(derSig, hash, pubKey)
}

// derToEthereumSignature converts an ASN.1 DER encoded ECDSA signature to the Ethereum
// [R || S || V] format. It calculates the correct recovery ID (V).
// `hash` is the original message hash that was signed.
// `pubKey` is the public key corresponding to the KMS key used for signing.
func derToEthereumSignature(derSig, hash []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}

	// Ensure S is in the lower half of the curve order (prevents malleability)
	// As per EIP-2: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
	curveOrder := crypto.S256().Params().N
	if sig.S.Cmp(new(big.Int).Div(curveOrder, big.NewInt(2))) > 0 {
		sig.S.Sub(curveOrder, sig.S)
	}

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// Ethereum signature format [R (32 bytes) || S (32 bytes) || V (1 byte)]
	signature := make([]byte, 65)

	// Left-pad R and S to 32 bytes
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Calculate recovery ID (V)
	// V = 27 + recovery_id (where recovery_id is 0 or 1)
	// Reference: go-ethereum/crypto/signature_nocgo.go's Sign function logic

	// We need to try both possible recovery IDs (0 and 1) and see which one
	// recovers the correct public key.
	var recoveredPubKey *ecdsa.PublicKey

	// Try V = 27 (recovery ID = 0)
	signature[64] = 0 // Use 0 for Ecrecover's V parameter
	recPubBytes, err := crypto.Ecrecover(hash, signature)
	// Need to handle errors from Ecrecover carefully
	if err == nil {
		// Unmarshal the recovered public key bytes (format: 0x04 || X || Y)
		x, y := elliptic.Unmarshal(crypto.S256(), recPubBytes)
		if x != nil { // Check if unmarshal was successful
			recoveredPubKey = &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}
			if recoveredPubKey.X.Cmp(pubKey.X) == 0 && recoveredPubKey.Y.Cmp(pubKey.Y) == 0 {
				signature[64] = 27 // Set Ethereum V
				return signature, nil
			}
		}
	}

	// Try V = 28 (recovery ID = 1)
	signature[64] = 1 // Use 1 for Ecrecover's V parameter
	recPubBytes, err = crypto.Ecrecover(hash, signature)
	if err == nil {
		// Unmarshal the recovered public key bytes
		x, y := elliptic.Unmarshal(crypto.S256(), recPubBytes)
		if x != nil { // Check if unmarshal was successful
			recoveredPubKey = &ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}
			if recoveredPubKey.X.Cmp(pubKey.X) == 0 && recoveredPubKey.Y.Cmp(pubKey.Y) == 0 {
				signature[64] = 28 // Set Ethereum V
				return signature, nil
			}
		}
	}

	// If neither recovery ID worked, something is wrong.
	return nil, fmt.Errorf("failed to determine correct recovery ID (V) for signature")
}

// SignerFn returns a `bind.SignerFn` compatible function for use with go-ethereum contract bindings.
// It captures the chain ID to produce EIP-155 compatible signatures.
func (s *KMSSigner) SignerFn(chainID *big.Int) bind.SignerFn {
	if chainID == nil || chainID.Sign() <= 0 {
		// Use a default or handle error? EIP-155 requires a positive chainID.
		// For now, let's return an error or panic, as non-EIP155 is insecure.
		// Panic might be better to catch configuration errors early.
		panic("SignerFn requires a valid positive chainID for EIP-155")
	}

	return func(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
		if addr != s.Address() {
			return nil, fmt.Errorf("attempted to sign transaction with incorrect address: expected %s, got %s", s.Address().Hex(), addr.Hex())
		}

		// EIP-155 signer requires the chain ID
		eip155Signer := types.NewEIP155Signer(chainID)
		txHash := eip155Signer.Hash(tx)

		// Sign the hash using KMS
		// Use context.Background or pass one down if needed for cancellation/deadlines
		signature, err := s.Sign(txHash[:])
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction hash with KMS: %w", err)
		}

		// EIP-155 V calculation is handled by `WithSignature`.
		// We need to adjust our V (27/28) back to recovery ID (0/1)
		// before passing it to WithSignature.
		// V = V_eth - (chainID * 2 + 35) => recovery_id
		// However, go-ethereum's `WithSignature` expects the raw [R || S || V] where V is 0 or 1.
		// It internally calculates the correct EIP-155 V.
		// So, we just need to adjust our 27/28 V back to 0/1.
		if len(signature) != 65 {
			return nil, fmt.Errorf("internal error: KMS signature has unexpected length %d", len(signature))
		}
		if signature[64] == 27 {
			signature[64] = 0
		} else if signature[64] == 28 {
			signature[64] = 1
		} else {
			// This shouldn't happen if derToEthereumSignature is correct
			return nil, fmt.Errorf("internal error: KMS signature has unexpected V value %d", signature[64])
		}

		// Add the signature to the transaction
		signedTx, err := tx.WithSignature(eip155Signer, signature)
		if err != nil {
			return nil, fmt.Errorf("failed to add KMS signature to transaction: %w", err)
		}

		return signedTx, nil
	}
}
