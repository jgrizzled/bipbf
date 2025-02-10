package bip39

import "testing"

func TestDeriveAddress(t *testing.T) {
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	expectedAddress := "bc1q7327vh7z7fardnla4dpmztcnewn80hcz7d4y0g" // m/84'/0'/0'/0/0
	password := "test"

	// Derive the address from the mnemonic using the provided function.
	addr, err := GetAddressFromMnemonic(mnemonic, password, 0, true, 0)
	if err != nil {
		t.Fatalf("Error deriving address: %v", err)
	}

	// Compare the derived address to the expected address.
	if addr.EncodeAddress() != expectedAddress {
		t.Fatalf("Expected address %s, got %s", expectedAddress, addr.EncodeAddress())
	}
}
