package signer

import (
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestDERToEthereumSignature(t *testing.T) {
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

	convertedSig, err := derToEthereumSignature(derSignature, hash, &privateKey.PublicKey)
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
}
