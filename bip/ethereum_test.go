package bip

import (
	"strings"
	"testing"
)

func TestGetEthereumAddressFromMnemonic(t *testing.T) {
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	expectedAddress := strings.ToLower("0xEAD855DA50ac7bb694746401BCda4d148F96dAd5") // Derived from m/44'/60'/0'/0/0
	password := "test"
	address, err := GetEthereumAddressFromMnemonic(mnemonic, password)
	if err != nil {
		t.Fatalf("Error deriving Ethereum address: %v", err)
	}

	if address != expectedAddress {
		t.Fatalf("Expected address %s, got %s", expectedAddress, address)
	}
}
