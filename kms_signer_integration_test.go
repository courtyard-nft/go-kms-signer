package signer

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestKeyConfig struct {
	KeyName string
}

func getTestKeyConfig(t *testing.T) TestKeyConfig {
	keyName := os.Getenv("TEST_KMS_KEY_NAME")
	if keyName == "" {
		t.Skip("TEST_KMS_KEY_NAME not set, skipping integration test")
	}

	return TestKeyConfig{
		KeyName: keyName,
	}
}

func TestKMSSignerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := getTestKeyConfig(t)
	ctx := context.Background()

	signer, err := NewKMSSigner(ctx, KMSSignerConfig{
		KeyName: config.KeyName,
	})
	require.NoError(t, err)
	defer signer.Close()

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
			signature, err := signer.Sign(ctx, hash)
			require.NoError(t, err)

			assert.Equal(t, 65, len(signature))

			assert.True(t, signature[64] >= 27, "v value should be >= 27")
			sigCopy := make([]byte, len(signature))
			copy(sigCopy, signature)
			sigCopy[64] -= 27

			_, err = crypto.Ecrecover(hash, sigCopy)
			assert.NoError(t, err, "should be able to recover public key from signature")
		})
	}
}

func TestKMSSignerIntegrationRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := getTestKeyConfig(t)
	ctx := context.Background()

	signer, err := NewKMSSigner(ctx, KMSSignerConfig{
		KeyName: config.KeyName,
	})
	require.NoError(t, err)
	defer signer.Close()

	message := []byte("Test message for concurrent signing")
	hash := crypto.Keccak256(message)
	var wg sync.WaitGroup
	numConcurrent := 5
	results := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := signer.Sign(ctx, hash)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	for err := range results {
		assert.NoError(t, err, "concurrent signing operation should succeed")
	}
}
