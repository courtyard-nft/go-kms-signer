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

	err := InitWithKMSSigner(ctx, KMSSignerConfig{
		KeyName: config.KeyName,
	})
	require.NoError(t, err)

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
			signature, err := Sign(tt.message)
			require.NoError(t, err)

			assert.Equal(t, 65, len(signature))

			assert.True(t, signature[64] >= 27, "v value should be >= 27")
			signature[64] -= 27

			hash := crypto.Keccak256(tt.message)
			_, err = crypto.Ecrecover(hash, signature)
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

	err := InitWithKMSSigner(ctx, KMSSignerConfig{
		KeyName: config.KeyName,
	})
	require.NoError(t, err)

	message := []byte("Test message for concurrent signing")
	var wg sync.WaitGroup
	numConcurrent := 5
	results := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Sign(message)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	for err := range results {
		assert.NoError(t, err, "concurrent signing operation should succeed")
	}
}
