package bipbf

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGetAddresses(t *testing.T) {
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	password := "test"

	t.Run("Bitcoin addresses", func(t *testing.T) {
		expectedAddresses := []string{
			"bc1q7327vh7z7fardnla4dpmztcnewn80hcz7d4y0g", // account 0, index 0
			"bc1q7pwzp2jwrnkf4fpmvha8mz88hvada5q9jurl8a", // account 0, index 1
			"bc1qmr46sndv5zf648fmnjd5lw9stk63nfwhpgl9tj", // account 1, index 0
			"bc1qsty8nqer4nulr9f6dpw9m3dch5zpw3gmxqkqwg", // account 1, index 1
		}

		// Derive addresses for accounts 0-1 and indexes 0-1
		addrs, err := GetAddresses("btc-bech32", mnemonic, password, 0, 1, 0, 1)
		if err != nil {
			t.Fatalf("Error deriving Bitcoin addresses: %v", err)
		}

		if len(addrs) != len(expectedAddresses) {
			t.Fatalf("Expected %d addresses, got %d", len(expectedAddresses), len(addrs))
		}

		for i, expectedAddr := range expectedAddresses {
			if addrs[i] != expectedAddr {
				t.Errorf("Bitcoin address %d: expected %s, got %s", i, expectedAddr, addrs[i])
			}
		}
	})

	t.Run("Ethereum addresses", func(t *testing.T) {
		expectedAddresses := []string{
			strings.ToLower("0xEAD855DA50ac7bb694746401BCda4d148F96dAd5"), // account 0, index 0
			strings.ToLower("0x4427B403a7Bc9e45Cf48f3caEdB011978f82AEF1"), // account 0, index 1
			strings.ToLower("0xBba2162CA8b18D3210B33Dc26cADaF1DfA579060"), // account 0, index 2
		}

		addresses, err := GetAddresses("eth", mnemonic, password, 0, 0, 0, 2)
		if err != nil {
			t.Fatalf("Error deriving Ethereum addresses: %v", err)
		}

		if len(addresses) != len(expectedAddresses) {
			t.Fatalf("Expected %d addresses, got %d", len(expectedAddresses), len(addresses))
		}

		for i, expectedAddr := range expectedAddresses {
			if strings.ToLower(addresses[i]) != expectedAddr {
				t.Errorf("Ethereum address %d: expected %s, got %s", i, expectedAddr, addresses[i])
			}
		}
	})

	t.Run("Invalid address type", func(t *testing.T) {
		_, err := GetAddresses("INVALID", mnemonic, password, 0, 0, 0, 0)
		if err == nil {
			t.Error("Expected error for invalid address type, got nil")
		}
	})

	t.Run("Invalid mnemonic", func(t *testing.T) {
		_, err := GetAddresses("btc-bech32", "invalid mnemonic", password, 0, 0, 0, 0)
		if err == nil {
			t.Error("Expected error for invalid mnemonic, got nil")
		}
	})

	t.Run("Invalid account range", func(t *testing.T) {
		_, err := GetAddresses("btc-bech32", mnemonic, password, 1, 0, 0, 0)
		if err == nil {
			t.Error("Expected error for invalid account range, got nil")
		}
	})

	t.Run("Invalid index range", func(t *testing.T) {
		_, err := GetAddresses("btc-bech32", mnemonic, password, 0, 0, 1, 0)
		if err == nil {
			t.Error("Expected error for invalid index range, got nil")
		}
	})
}

func BenchmarkGetAddresses(b *testing.B) {
	// Same mnemonic for all runs
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"

	// Reset the timer to exclude setup time.
	b.ResetTimer()
	start := time.Now() // start the timer
	for n := 0; n < b.N; n++ {
		// Call GetAddresses 1000 times, each with a different password.
		for i := 0; i < 1000; i++ {
			// Build an incremented password ("test0", "test1", etc.)
			password := fmt.Sprintf("test%d", i)
			// For simplicity, derive a single address (account 0, index 0).
			_, err := GetAddresses("btc-bech32", mnemonic, password, 0, 0, 0, 0)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	elapsed := time.Since(start)
	totalPasswords := b.N * 1000
	passwordsPerSecond := float64(totalPasswords) / elapsed.Seconds()
	// Use Logf so that the output is associated with the benchmark result.
	b.Logf("Passwords per second: %.2f", passwordsPerSecond)
}
