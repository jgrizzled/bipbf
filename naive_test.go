package bipbf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNaiveBruteForce(t *testing.T) {
	// Create a temporary directory for the test database
	tmpDir, err := os.MkdirTemp("", "naive-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	dbPath := filepath.Join(tmpDir, "test.db")

	// Test cases for both BTC and ETH
	testCases := []struct {
		name        string
		mnemonic    string
		password    string
		address     string
		addressType string
	}{
		{
			name:        "Bitcoin Native SegWit",
			mnemonic:    "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define",
			password:    "a",
			address:     "bc1q0dc8v2u2m8twr8kt5x4l8544g9dnc2z79fwvw2",
			addressType: "btc-nativesegwit",
		},
		{
			name:        "Ethereum",
			mnemonic:    "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define",
			password:    "a",
			address:     strings.ToLower("0xCF6e22ad28Bead46d844e111B48b259A5314E7c3"),
			addressType: "eth",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := BruteForceConfig{
				Charset:     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ ",
				Workers:     8,
				BatchSize:   10000,
				MinLen:      1,
				MaxLen:      1,
				DbPath:      dbPath,
				Mnemonic:    tc.mnemonic,
				Address:     tc.address,
				AddressType: tc.addressType,
			}

			result, err := NaiveBruteForce(config)
			if err != nil {
				t.Fatalf("NaiveBruteForce failed: %v", err)
			}

			if !result.Found {
				t.Error("Expected to find password, but didn't")
			}

			if result.FoundPassword != tc.password {
				t.Errorf("Expected to find %q, but found %q", tc.password, result.FoundPassword)
			}
		})
	}
}

func BenchmarkNaiveBruteForce(b *testing.B) {
	// Create a temporary directory for the test database
	tmpDir, err := os.MkdirTemp("", "naive-benchmark-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	dbPath := filepath.Join(tmpDir, "test.db")

	// Use the same mnemonic and password as the test
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	address := "bc1qftzutf0w24y28lhwjuduyuwh7asuljnv8trdrt" // Password: 123

	config := BruteForceConfig{
		Charset:     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ ",
		Workers:     8,
		BatchSize:   1000,
		MinLen:      1,
		MaxLen:      3,
		DbPath:      dbPath,
		Mnemonic:    mnemonic,
		Address:     address,
		AddressType: "btc-nativesegwit",
	}

	b.ResetTimer() // Reset the timer before the actual benchmark

	result, err := NaiveBruteForce(config)
	if err != nil {
		b.Fatalf("NaiveBruteForce failed: %v", err)
	}

	if !result.Found {
		b.Error("Expected to find password, but didn't")
	}

	if result.FoundPassword != "123" {
		b.Errorf("Expected to find %q, but found %q", "123", result.FoundPassword)
	}
}
