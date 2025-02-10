package bip

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/sha3"
)

// GetEthereumAddressFromMnemonic derives an Ethereum address using the BIP44 derivation path m/44'/60'/0'/0/0.
func GetEthereumAddressFromMnemonic(mnemonic, password string) (string, error) {
	// Convert the mnemonic to a seed.
	seed, err := ConvertMnemonicToSeed(mnemonic, password)
	if err != nil {
		return "", err
	}

	// Create the master key from the seed (the chain parameters here are not used for Ethereum).
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	// Derive the BIP44 path: m/44'/60'/0'/0/0
	purpose, err := masterKey.Derive(44 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return "", err
	}
	coinType, err := purpose.Derive(60 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return "", err
	}
	accountKey, err := coinType.Derive(0 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return "", err
	}
	changeKey, err := accountKey.Derive(0)
	if err != nil {
		return "", err
	}
	addressKey, err := changeKey.Derive(0)
	if err != nil {
		return "", err
	}

	// Get the uncompressed public key.
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return "", err
	}
	uncompressedPubKey := pubKey.SerializeUncompressed() // 65 bytes (first byte is 0x04)

	// Compute Keccak256 hash of the public key (exclude the first byte).
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(uncompressedPubKey[1:]) // skip the 0x04 prefix
	hash := hasher.Sum(nil)              // 32-byte hash

	// Ethereum address is the last 20 bytes of the hash with a "0x" prefix.
	ethAddress := fmt.Sprintf("0x%x", hash[12:])
	return ethAddress, nil
}
