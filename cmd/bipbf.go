package main

import (
	"bipbf"
	"bipbf/strats/naive"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
)

func main() {
	//--------------------------------
	// Parse flags
	//--------------------------------
	var naiveFlag bool
	flag.BoolVar(&naiveFlag, "naive", false, "Enable naive brute forcing mode")

	var dbPathFlag string
	flag.StringVar(&dbPathFlag, "dbPath", "db.sqlite", "Path to SQLite database file")

	var charsetFlag string
	flag.StringVar(&charsetFlag, "charset", "", "Charset to use (default loads from charset.txt if present, else alphanumeric)")

	var workersFlag int
	flag.IntVar(&workersFlag, "workers", 0, "Number of worker goroutines (default is numCPU - 1)")

	var batchSizeFlag int
	flag.IntVar(&batchSizeFlag, "batchSize", 10000, "Number of passwords per batch")

	var minLenFlag int
	flag.IntVar(&minLenFlag, "minLen", 1, "Minimum length of passwords to brute force")

	var maxLenFlag int
	flag.IntVar(&maxLenFlag, "maxLen", 4, "Maximum length of passwords to brute force")

	var mnemonicFlag string
	flag.StringVar(&mnemonicFlag, "mnemonic", "", "Mnemonic to test passwords against (default loads from mnemonic.txt)")

	var addressFlag string
	flag.StringVar(&addressFlag, "address", "", "Address to find (default loads from address.txt)")

	var addressTypeFlag string
	flag.StringVar(&addressTypeFlag, "addressType", "", "Address type: 'btc-nativesegwit' or 'eth'")

	flag.Parse()

	// We only have one mode right now: --naive
	// If the user didn't pass --naive or if they passed multiple modes, we error.
	// (This is a naive check — if in the future we have more modes, we'd do a more robust check.)
	if !naiveFlag {
		log.Fatalf("Please provide exactly one mode: --naive")
	}

	//--------------------------------
	// Handle defaults
	//--------------------------------
	// charset
	finalCharset := ""
	if charsetFlag != "" {
		finalCharset = charsetFlag
	} else {
		// Try to load from charset.txt
		if _, err := os.Stat("charset.txt"); err == nil {
			bytes, err := os.ReadFile("charset.txt")
			if err != nil {
				log.Fatalf("Failed to read charset.txt: %v", err)
			}
			finalCharset = strings.TrimSpace(string(bytes))
		}
		// If still empty, default to alphanumeric
		if finalCharset == "" {
			finalCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ "
		}
	}

	// Sort the charset by lex order to ensure consistency
	runes := []rune(finalCharset)
	sort.Slice(runes, func(i, j int) bool {
		return runes[i] < runes[j]
	})
	finalCharset = string(runes)

	// workers
	finalWorkers := workersFlag
	if finalWorkers == 0 {
		finalWorkers = runtime.NumCPU() - 1
		if finalWorkers < 1 {
			finalWorkers = 1
		}
	}

	// Load mnemonic
	finalMnemonic := mnemonicFlag
	if finalMnemonic == "" {
		// Check env var first
		if envMnemonic := os.Getenv("BIPBF_MNEMONIC"); envMnemonic != "" {
			finalMnemonic = envMnemonic
		} else if bytes, err := os.ReadFile("mnemonic.txt"); err == nil {
			finalMnemonic = strings.TrimSpace(string(bytes))
		}
	}
	if finalMnemonic == "" {
		log.Fatal("No --mnemonic provided, BIPBF_MNEMONIC env var not set, and mnemonic.txt missing or empty")
	}

	// Load address
	finalAddress := addressFlag
	if finalAddress == "" {
		// Check env var first
		if envAddress := os.Getenv("BIPBF_ADDRESS"); envAddress != "" {
			finalAddress = envAddress
		} else if bytes, err := os.ReadFile("address.txt"); err == nil {
			finalAddress = strings.TrimSpace(string(bytes))
		}
	}
	if finalAddress == "" {
		log.Fatal("No --address provided, BIPBF_ADDRESS env var not set, and address.txt missing or empty")
	}

	// Validate address type
	finalAddressType := addressTypeFlag
	if finalAddressType == "" {
		// Check env var
		if envAddressType := os.Getenv("BIPBF_ADDRESS_TYPE"); envAddressType != "" {
			finalAddressType = envAddressType
		}
	}
	if finalAddressType != "btc-nativesegwit" && finalAddressType != "eth" {
		log.Fatal("--addressType or BIPBF_ADDRESS_TYPE env var must be 'btc-nativesegwit' or 'eth'")
	}

	// Initialize DB connection at the top level
	db, err := bipbf.InitDB(dbPathFlag)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	config := naive.BruteForceConfig{
		Charset:     finalCharset,
		Workers:     finalWorkers,
		BatchSize:   batchSizeFlag,
		MinLen:      minLenFlag,
		MaxLen:      maxLenFlag,
		Mnemonic:    finalMnemonic,
		Address:     finalAddress,
		AddressType: finalAddressType,
	}

	fmt.Printf("Charset: %q\n", config.Charset)
	fmt.Printf("Workers: %d\n", config.Workers)
	fmt.Printf("Address to find: %s\n", config.Address)
	fmt.Printf("Batch size: %d\n", config.BatchSize)
	fmt.Printf("minLen: %d, maxLen: %d\n", config.MinLen, config.MaxLen)

	result, err := naive.NaiveBruteForce(db, config)
	if err != nil {
		log.Fatalf("Brute force failed: %v", err)
	}

	if result.Found {
		fmt.Printf("Found password: %s\n", result.FoundPassword)
	} else {
		fmt.Println("Password not found in the given range.")
	}
}
