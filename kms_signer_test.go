package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKMSClient struct {
	privateKey *ecdsa.PrivateKey
}

func newMockKMSClient(t *testing.T) *KMSSigner {
	privateKeyHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err, "Failed to decode private key hex")

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	require.NoError(t, err, "Failed to create private key")

	mock := &mockKMSClient{
		privateKey: privateKey,
	}

	signer := &KMSSigner{
		client:  mock,
		keyName: "test-key",
	}
	
	err = signer.fetchAndCachePublicKey(context.Background())
	require.NoError(t, err, "Failed to fetch and cache public key")
	
	return signer
}

func (m *mockKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
	pubKeyBytes := crypto.FromECDSAPub(&m.privateKey.PublicKey)
	
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return &kmspb.PublicKey{
		Pem:       string(pemBytes),
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
	}, nil
}

func (m *mockKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	hash := req.GetDigest().GetSha256()

	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}

	signature, err := crypto.Sign(hash, m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	derSignature, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DER signature: %w", err)
	}

	return &kmspb.AsymmetricSignResponse{
		Signature: derSignature,
	}, nil
}

func (m *mockKMSClient) Close() error {
	return nil
}

func TestKMSSignerWithMock(t *testing.T) {
	signer := newMockKMSClient(t)

	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "Simple message",
			message: []byte("Hello, world!"),
		},
		{
			name:    "Empty message",
			message: []byte{},
		},
		{
			name:    "Long message",
			message: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := crypto.Keccak256(tt.message)
			signature, err := signer.Sign(hash)
			require.NoError(t, err)

			assert.Equal(t, 65, len(signature))

			if signature[64] != 0x1b && signature[64] != 0x1c {
				t.Fatalf("Invalid recovery ID: %x", signature[64])
			}

			signature[64] -= 27

			recoveredPub, err := crypto.Ecrecover(hash, signature)
			require.NoError(t, err)

			x, y := elliptic.Unmarshal(crypto.S256(), recoveredPub)
			recoveredKey := &ecdsa.PublicKey{
				X: x,
				Y: y,
			}

			assert.NotNil(t, recoveredKey.X)
			assert.NotNil(t, recoveredKey.Y)
		})
	}
}

func TestDerToEthereumSignature(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err, "Failed to generate test key pair")

	message := []byte("test message")
	hash := crypto.Keccak256(message)

	ethSig, err := crypto.Sign(hash, privateKey)
	require.NoError(t, err, "Failed to sign message")

	r := new(big.Int).SetBytes(ethSig[:32])
	s := new(big.Int).SetBytes(ethSig[32:64])

	derSignature, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	require.NoError(t, err, "Failed to create DER signature")

	signer := &KMSSigner{}

	tests := []struct {
		name string
	}{
		{
			name: "Standard Ethereum signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			convertedSig, err := signer.derToEthereumSignature(derSignature, hash, &privateKey.PublicKey)
			require.NoError(t, err, "Failed to convert DER signature to Ethereum format")

			require.Equal(t, 65, len(convertedSig), "Invalid signature length")

			if convertedSig[64] != 0x1b && convertedSig[64] != 0x1c {
				t.Fatalf("Invalid recovery ID for standard signature: %x", convertedSig[64])
			}

			sigForVerify := make([]byte, len(convertedSig))
			copy(sigForVerify, convertedSig)

			sigForVerify[64] -= 27 // Standard Ethereum signature

			require.Equal(t, ethSig[:32], convertedSig[:32], "R value mismatch")
			require.Equal(t, ethSig[32:64], convertedSig[32:64], "S value mismatch")

		})
	}
}

func TestEthereumSignature(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err, "Failed to generate test key pair")

	message := []byte("test message")
	hash := crypto.Keccak256(message)

	signature, err := crypto.Sign(hash, privateKey)
	require.NoError(t, err, "Failed to sign message")

	t.Logf("Signature length: %d", len(signature))
	t.Logf("R: %x", signature[:32])
	t.Logf("S: %x", signature[32:64])
	t.Logf("V: %x", signature[64])

	recoveredPub, err := crypto.Ecrecover(hash, signature)
	require.NoError(t, err, "Failed to recover public key")

	x, y := new(big.Int), new(big.Int)
	x.SetBytes(recoveredPub[1:33])
	y.SetBytes(recoveredPub[33:])
	recoveredKey := &ecdsa.PublicKey{
		X: x,
		Y: y,
	}

	assert.Equal(t, privateKey.PublicKey.X, recoveredKey.X, "Recovered public key X mismatch")
	assert.Equal(t, privateKey.PublicKey.Y, recoveredKey.Y, "Recovered public key Y mismatch")
}

func TestEIP155TransactionSigning(t *testing.T) {

	privateKeyHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	require.NoError(t, err, "Failed to decode private key hex")

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	require.NoError(t, err, "Failed to create private key")

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	chainIDs := []*big.Int{
		big.NewInt(1), // Ethereum Mainnet
	}

	for _, chainID := range chainIDs {
		t.Run(fmt.Sprintf("ChainID_%d", chainID), func(t *testing.T) {
			tx := types.NewTransaction(
				0,                      // nonce
				common.Address{},       // to
				big.NewInt(0),          // amount
				uint64(21000),          // gasLimit
				big.NewInt(1000000000), // gasPrice
				[]byte{},               // data
			)

			ethSigner := types.NewEIP155Signer(chainID)
			signedTx, err := types.SignTx(tx, ethSigner, privateKey)
			require.NoError(t, err)

			sender, err := types.Sender(ethSigner, signedTx)
			require.NoError(t, err)

			require.Equal(t, address.Hex(), sender.Hex())

			t.Log("Testing with KMS signer")
			signer := newMockKMSClient(t)

			kmsAddress, err := signer.GetWalletAddress(context.Background())
			require.NoError(t, err)

			signerFn := signer.SignerFn(chainID)

			tx2 := types.NewTransaction(
				0,                      // nonce
				common.Address{},       // to
				big.NewInt(0),          // amount
				uint64(21000),          // gasLimit
				big.NewInt(1000000000), // gasPrice
				[]byte{},               // data
			)

			signedTx2, err := signerFn(common.HexToAddress(kmsAddress), tx2)
			require.NoError(t, err)

			sender2, err := types.Sender(ethSigner, signedTx2)
			require.NoError(t, err)
			require.Equal(t, common.HexToAddress(kmsAddress).Hex(), sender2.Hex())
		})
	}
}
