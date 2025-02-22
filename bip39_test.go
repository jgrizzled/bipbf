package bipbf

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGetAddresses(t *testing.T) {
	// Test data setup
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	password := "test"

	tests := []struct {
		name          string
		addrType      string
		mnemonic      string
		password      string
		startAccount  int
		endAccount    int
		startIndex    int
		endIndex      int
		expectedAddrs []string
		expectError   bool
	}{
		{
			name:         "Bitcoin Bech32",
			addrType:     "btc-bech32",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 0,
			endAccount:   1,
			startIndex:   0,
			endIndex:     1,
			expectedAddrs: []string{
				"bc1q7327vh7z7fardnla4dpmztcnewn80hcz7d4y0g", // account 0, index 0
				"bc1q7pwzp2jwrnkf4fpmvha8mz88hvada5q9jurl8a", // account 0, index 1
				"bc1qmr46sndv5zf648fmnjd5lw9stk63nfwhpgl9tj", // account 1, index 0
				"bc1qsty8nqer4nulr9f6dpw9m3dch5zpw3gmxqkqwg", // account 1, index 1
			},
			expectError: false,
		},
		{
			name:         "Bitcoin Segwit",
			addrType:     "btc-segwit",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 0,
			endAccount:   1,
			startIndex:   0,
			endIndex:     1,
			expectedAddrs: []string{
				"3R1Wxro6AGazBvQVSKyvkNqvssxdGPivz9", // account 0, index 0
				"347DLrfztJBc4oTQuaN8ixfNFxvwto35G3", // account 0, index 1
				"33noPkxrbzw6m5XKSxKyveCi54gXtzq5fU", // account 1, index 0
				"3HK3JrEQ5KqzuhKUDakxNfPhrfBPuKEV3J", // account 1, index 1
			},
			expectError: false,
		},
		{
			name:         "Bitcoin Legacy",
			addrType:     "btc-legacy",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 0,
			endAccount:   1,
			startIndex:   0,
			endIndex:     1,
			expectedAddrs: []string{
				"1FzwLAPh2jHZtWmGm4CHRbKae8gQzdiMTo", // account 0, index 0
				"12SR2X2gJXM69oezkNp34n3wrxoMmTtkQE", // account 0, index 1
				"1GtbZvCVQoyvT4UTCnZ24r8MELd3HxS737", // account 1, index 0
				"1GBYvGv9Ab6Lpq2Mi6RGJJ62rmyrBaDgQb", // account 1, index 1
			},
			expectError: false,
		},
		{
			name:         "Ethereum addresses",
			addrType:     "eth",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 0,
			endAccount:   0,
			startIndex:   0,
			endIndex:     2,
			expectedAddrs: []string{
				"0xEAD855DA50ac7bb694746401BCda4d148F96dAd5", // account 0, index 0
				"0x4427B403a7Bc9e45Cf48f3caEdB011978f82AEF1", // account 0, index 1
				"0xBba2162CA8b18D3210B33Dc26cADaF1DfA579060", // account 0, index 2
			},
			expectError: false,
		},
		{
			name:         "Invalid address type",
			addrType:     "INVALID",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 0,
			endAccount:   0,
			startIndex:   0,
			endIndex:     0,
			expectError:  true,
		},
		{
			name:         "Invalid mnemonic",
			addrType:     "btc-bech32",
			mnemonic:     "invalid mnemonic",
			password:     password,
			startAccount: 0,
			endAccount:   0,
			startIndex:   0,
			endIndex:     0,
			expectError:  true,
		},
		{
			name:         "Invalid account range",
			addrType:     "btc-bech32",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 1,
			endAccount:   0,
			startIndex:   0,
			endIndex:     0,
			expectError:  true,
		},
		{
			name:         "Invalid index range",
			addrType:     "btc-bech32",
			mnemonic:     mnemonic,
			password:     password,
			startAccount: 0,
			endAccount:   0,
			startIndex:   1,
			endIndex:     0,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs, err := GetAddresses(tt.addrType, tt.mnemonic, tt.password,
				tt.startAccount, tt.endAccount, tt.startIndex, tt.endIndex)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(addrs) != len(tt.expectedAddrs) {
				t.Fatalf("Expected %d addresses, got %d", len(tt.expectedAddrs), len(addrs))
			}

			for i, expectedAddr := range tt.expectedAddrs {
				if !strings.EqualFold(addrs[i], expectedAddr) {
					t.Errorf("Address %d: expected %s, got %s", i, expectedAddr, addrs[i])
				}
			}
		})
	}
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
