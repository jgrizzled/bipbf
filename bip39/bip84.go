// Adapted from github.com/KaiWitt/go-bip84
// Fixed some dependency issues
package bip39

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"

	"github.com/tyler-smith/go-bip32"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/tyler-smith/go-bip39"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

var (
	zprvVersion, _        = hex.DecodeString("04b2430c") // bip-0084
	zpubVersion, _        = hex.DecodeString("04b24746") // bip-0084
	bip84Purpose   uint32 = 84                           // bip-0084
	bip84CoinType  uint32 = 0                            // bip-0084
)

// ConvertMnemonicToSeed converts a mnemonic to a bip39 seed.
// If the mnemonic is unvalid an error will be returned.
// Password will be ignored if string is empty "".
func ConvertMnemonicToSeed(mnemonic, password string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("Mnemonic is not valid")
	}

	return bip39.NewSeed(mnemonic, password), nil
}

// DeriveChangeAndIndex derives the account type and an index from an extended key.
// If isReceive is true the account type is 0, else it's 1.
func DeriveChangeAndIndex(extended *hdkeychain.ExtendedKey, isReceive bool, index uint32) (*hdkeychain.ExtendedKey, error) {
	var err error
	var internalKey *hdkeychain.ExtendedKey
	if isReceive {
		internalKey, err = extended.Derive(0)
	} else {
		internalKey, err = extended.Derive(1)
	}
	if err != nil {
		return nil, err
	}
	extendedKey, err := internalKey.Derive(index)
	if err != nil {
		return nil, err
	}

	return extendedKey, nil
}

// DeriveHardenedKeys derives hardened purpose, coin and account keys from a seed.
// The purpose is 84 (bip-0084) and coin is 0.
func DeriveHardenedKeys(seed []byte, account uint32) (*hdkeychain.ExtendedKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	purposeKey, err := masterKey.Derive(bip84Purpose + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}
	coinTypeKey, err := purposeKey.Derive(bip84CoinType + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}
	accountKey, err := coinTypeKey.Derive(account + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	return accountKey, nil
}

// EncodeBech32 encodes a public key to a bech32 address (P2WPKH)
func EncodeBech32(pubKey *btcec.PublicKey) (*btcutil.AddressWitnessPubKeyHash, error) {
	compressed := pubKey.SerializeCompressed()
	hash160 := btcutil.Hash160(compressed)
	address, err := btcutil.NewAddressWitnessPubKeyHash(hash160, &chaincfg.MainNetParams)
	if err != nil {
		log.Println("Unable to create P2WPKH address from hash160 of compressed public key:", err)
		return nil, err
	}

	return address, nil
}

// Generate12WordMnemonic generates a new 12 word mnemonic which can be used to derive addresses and private keys
func Generate12WordMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		log.Println("Unable to generate entropy:", err)
		return "", err
	}

	return GenerateMnemonicFromEntropy(entropy)
}

// Generate24WordMnemonic generates a new 24 word mnemonic which can be used to derive addresses and private keys
func Generate24WordMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Println("Unable to generate entropy:", err)
		return "", err
	}

	return GenerateMnemonicFromEntropy(entropy)
}

// GenerateMnemonicFromEntropy generates a new mnemonic which can be used to derive addresses and private keys
func GenerateMnemonicFromEntropy(entropy []byte) (string, error) {
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Println("Unable to generate mnemonic from entropy:", err)
		return "", err
	}
	return mnemonic, nil
}

// GenerateSeed generates a new seed which can be used to derive addresses and private keys
func GenerateSeed() ([]byte, error) {
	return bip32.NewSeed()
}

// GetAddressFromMnemonic derives an address from a mnemonic by account, account type and index.
// Password for mnemonic will be ignored if string is empty "".
func GetAddressFromMnemonic(mnemonic, password string, account uint32, isReceive bool, index uint32) (*btcutil.AddressWitnessPubKeyHash, error) {
	seed, err := ConvertMnemonicToSeed(mnemonic, password)
	if err != nil {
		log.Println("Unable to read mnemonic:", err)
		return nil, err
	}
	address, err := GetAddressFromSeed(seed, account, isReceive, index)
	if err != nil {
		log.Println("Unable to derive bech32 encoded address from seed:", err)
		return nil, err
	}

	return address, nil
}

// GetAddressFromSeed derives an address from a seed by account, account type and index.
func GetAddressFromSeed(seed []byte, account uint32, isReceive bool, index uint32) (*btcutil.AddressWitnessPubKeyHash, error) {
	zpubKey, err := GetZPubKeyFromSeed(seed, account)
	if err != nil {
		log.Println("Unable to derive extended public key from seed:", err)
		return nil, err
	}
	address, err := GetAddressFromZPubKey(zpubKey, isReceive, index)
	if err != nil {
		log.Println("Unable to derive bech32 encoded address from extended public key:", err)
		return nil, err
	}
	return address, nil
}

// GetAddressFromZPubKey derives an address from an extended public key by account type and index.
func GetAddressFromZPubKey(zpub *hdkeychain.ExtendedKey, isReceive bool, index uint32) (*btcutil.AddressWitnessPubKeyHash, error) {
	extendedKey, err := DeriveChangeAndIndex(zpub, isReceive, index)
	if err != nil {
		log.Println("Unable to derive change/index from extended key:", err)
		return nil, err
	}
	pubKey, err := extendedKey.ECPubKey()
	if err != nil {
		log.Println("Unable to convert extended index public key to public key:", err)
		return nil, err
	}

	return EncodeBech32(pubKey)
}

// GetAddressFromZPubKeyString parses an extended public key and derives an address from it by account type and index.
func GetAddressFromZPubKeyString(zpub string, isReceive bool, index uint32) (*btcutil.AddressWitnessPubKeyHash, error) {
	zpubKey, err := hdkeychain.NewKeyFromString(zpub)
	if err != nil {
		log.Println("Unable to read extended public key:", err)
		return nil, err
	}
	address, err := GetAddressFromZPubKey(zpubKey, isReceive, index)
	if err != nil {
		log.Println("Unable to derive bech32 encoded address from extended public key:", err)
		return nil, err
	}

	return address, nil
}

// GetWifFromMnemonic derives a private key as WIF (wallet import format) from a mnemonic by account, account type and index.
// Password for mnemonic will be ignored if string is empty "".
func GetWifFromMnemonic(mnemonic, password string, account uint32, isReceive bool, index uint32) (*btcutil.WIF, error) {
	seed, err := ConvertMnemonicToSeed(mnemonic, password)
	if err != nil {
		log.Println("Unable to read mnemonic:", err)
		return nil, err
	}
	wif, err := GetWifFromSeed(seed, account, isReceive, index)
	if err != nil {
		log.Println("Unable to derive WIF from seed:", err)
		return nil, err
	}

	return wif, nil
}

// GetWifFromSeed derives a private key as WIF (wallet import format) from a seed by account, account type and index.
func GetWifFromSeed(seed []byte, account uint32, isReceive bool, index uint32) (*btcutil.WIF, error) {
	accountKey, err := DeriveHardenedKeys(seed, account)
	if err != nil {
		log.Println("Unable to derive purpose/coin/account from extended key:", err)
		return nil, err
	}
	wif, err := GetWifFromZPrivKey(accountKey, isReceive, index)
	if err != nil {
		log.Println("Unable to derive WIF from extended private key:", err)
		return nil, err
	}

	return wif, nil
}

// GetWifFromZPrivKey derives a private key as WIF (wallet import format) from an extended private key by account type and index.
func GetWifFromZPrivKey(zpriv *hdkeychain.ExtendedKey, isReceive bool, index uint32) (*btcutil.WIF, error) {
	extendedKey, err := DeriveChangeAndIndex(zpriv, isReceive, index)
	if err != nil {
		log.Println("Unable to derive change/index from extended key:", err)
		return nil, err
	}
	privKey, err := extendedKey.ECPrivKey()
	if err != nil {
		log.Println("Unable to convert extended index private key to private key:", err)
		return nil, err
	}
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		log.Println("Unable to convert private key to WIF:", err)
		return nil, err
	}

	return wif, nil
}

// GetWifFromZPrivKeyString parses an extended private key and derives a private key as WIF (wallet import format) from it by account type and index.
func GetWifFromZPrivKeyString(zpriv string, isReceive bool, index uint32) (*btcutil.WIF, error) {
	zprivKey, err := hdkeychain.NewKeyFromString(zpriv)
	if err != nil {
		log.Println("Unable to read extended private key:", err)
		return nil, err
	}
	wif, err := GetWifFromZPrivKey(zprivKey, isReceive, index)
	if err != nil {
		log.Println("Unable to derive WIF from extended private key:", err)
		return nil, err
	}

	return wif, nil
}

// GetZPrivKeyFromMnemonic derives an extended private key from a mnemonic by account.
// Password for mnemonic will be ignored if string is empty "".
func GetZPrivKeyFromMnemonic(mnemonic, password string, account uint32) (*hdkeychain.ExtendedKey, error) {
	seed, err := ConvertMnemonicToSeed(mnemonic, password)
	if err != nil {
		log.Println("Unable to read mnemonic:", err)
		return nil, err
	}
	zprivKey, err := GetZPrivKeyFromSeed(seed, account)
	if err != nil {
		log.Println("Unable to derive extended private key from seed:", err)
		return nil, err
	}

	return zprivKey, nil
}

// GetZPrivKeyFromSeed derives an extended private key from a seed by account.
func GetZPrivKeyFromSeed(seed []byte, account uint32) (*hdkeychain.ExtendedKey, error) {
	accountKey, err := DeriveHardenedKeys(seed, account)
	if err != nil {
		log.Println("Unable to derive purpose/coin/account from extended key:", err)
		return nil, err
	}
	zprivKey, err := accountKey.ECPrivKey()
	if err != nil {
		log.Println("Unable to derive extended private key from account key:", err)
		return nil, err
	}
	fingerprint := make([]byte, 4)
	binary.BigEndian.PutUint32(fingerprint, accountKey.ParentFingerprint())

	return hdkeychain.NewExtendedKey(zprvVersion, zprivKey.Serialize(), accountKey.ChainCode(), fingerprint, accountKey.Depth(), accountKey.ChildIndex(), true), nil
}

// GetZPubKeyFromMnemonic derives an extended public key from a mnemonic by account.
// Password for mnemonic will be ignored if string is empty "".
func GetZPubKeyFromMnemonic(mnemonic, password string, account uint32) (*hdkeychain.ExtendedKey, error) {
	seed, err := ConvertMnemonicToSeed(mnemonic, password)
	if err != nil {
		log.Println("Unable to read mnemonic:", err)
		return nil, err
	}
	zpubKey, err := GetZPubKeyFromSeed(seed, account)
	if err != nil {
		log.Println("Unable to derive extended public key from seed:", err)
		return nil, err
	}

	return zpubKey, nil
}

// GetZPubKeyFromSeed derives an extended public key from a seed by account.
func GetZPubKeyFromSeed(seed []byte, account uint32) (*hdkeychain.ExtendedKey, error) {
	accountKey, err := GetZPrivKeyFromSeed(seed, account)
	if err != nil {
		log.Println("Unable to derive account key from seed:", err)
		return nil, err
	}
	zpubKey, err := accountKey.ECPubKey()
	if err != nil {
		log.Println("Unable to derive extended public key from account key:", err)
		return nil, err
	}
	fingerprint := make([]byte, 4)
	binary.BigEndian.PutUint32(fingerprint, accountKey.ParentFingerprint())

	return hdkeychain.NewExtendedKey(zpubVersion, zpubKey.SerializeCompressed(), accountKey.ChainCode(), fingerprint, accountKey.Depth(), accountKey.ChildIndex(), false), nil
}
