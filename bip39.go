package bipbf

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

// GetAddresses derives multiple cryptocurrency addresses from a mnemonic phrase
// using the appropriate BIP standard for the given address type:
// - BTC: BIP84 derivation path m/84'/0'/account'/0/index
// - ETH: BIP44 derivation path m/44'/60'/account'/0/index
func GetAddresses(addressType string, mnemonic, password string, startAccount, endAccount, startAddressIndex, endAddressIndex uint32) ([]string, error) {
	// Validate the mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is not valid")
	}

	if endAccount < startAccount {
		return nil, errors.New("endAccount must be greater than or equal to startAccount")
	}

	if endAddressIndex < startAddressIndex {
		return nil, errors.New("endAddressIndex must be greater than or equal to startAddressIndex")
	}

	// Convert the mnemonic to a seed
	seed := bip39.NewSeed(mnemonic, password)

	// Create master key
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	// Set up path parameters based on address type
	var purpose, coinType uint32
	switch addressType {
	case "btc-bech32":
		purpose = 84
		coinType = 0
	case "eth":
		purpose = 44
		coinType = 60
	default:
		return nil, fmt.Errorf("unsupported address type: %s", addressType)
	}

	// Derive the static part of the path
	purposeKey, err := masterKey.Derive(purpose + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}
	coinTypeKey, err := purposeKey.Derive(coinType + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	addressesPerAccount := endAddressIndex - startAddressIndex + 1
	totalAddresses := (endAccount - startAccount + 1) * addressesPerAccount
	addresses := make([]string, 0, totalAddresses)

	// Derive addresses for each account in the range
	for account := startAccount; account <= endAccount; account++ {
		accountKey, err := coinTypeKey.Derive(account + hdkeychain.HardenedKeyStart)
		if err != nil {
			return nil, err
		}
		change, err := accountKey.Derive(0)
		if err != nil {
			return nil, err
		}

		// Derive addresses for each index in the range
		for index := startAddressIndex; index <= endAddressIndex; index++ {
			addressKey, err := change.Derive(index)
			if err != nil {
				return nil, err
			}

			// Get the public key
			pubKey, err := addressKey.ECPubKey()
			if err != nil {
				return nil, err
			}

			var address string
			switch addressType {
			case "btc-bech32":
				compressed := pubKey.SerializeCompressed()
				hash160 := btcutil.Hash160(compressed)
				addr, err := btcutil.NewAddressWitnessPubKeyHash(hash160, &chaincfg.MainNetParams)
				if err != nil {
					return nil, err
				}
				address = addr.EncodeAddress()

			case "eth":
				uncompressedPubKey := pubKey.SerializeUncompressed()
				hasher := sha3.NewLegacyKeccak256()
				hasher.Write(uncompressedPubKey[1:]) // skip the 0x04 prefix
				hash := hasher.Sum(nil)
				address = fmt.Sprintf("0x%x", hash[12:])
			}

			addresses = append(addresses, address)
		}
	}

	return addresses, nil
}
