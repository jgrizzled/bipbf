package main

import (
	"bipbf"
	"bipbf/strats/exhaustive"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
)

func main() {
	var dbPathFlag string
	flag.StringVar(&dbPathFlag, "dbPath", "db.sqlite", "Path to SQLite database file")

	var dbSizeGBFlag int
	flag.IntVar(&dbSizeGBFlag, "dbSize", 0, "Max db size in GB (0 = use default)")

	var modeFlag string
	flag.StringVar(&modeFlag, "mode", "exhaustive", "Brute force mode: 'exhaustive' (more modes coming soon)")

	var mnemonicFlag string
	flag.StringVar(&mnemonicFlag, "mnemonic", "", "Mnemonic to test passwords against (not stored in DB)")

	var addressFlag string
	flag.StringVar(&addressFlag, "address", "", "Address to find")

	var addressTypeFlag string
	flag.StringVar(&addressTypeFlag, "addressType", "", "Address type: 'btc-bech32' or 'eth'")

	var lenFlag int
	flag.IntVar(&lenFlag, "len", 1, "Length of passwords to brute force")

	var workersFlag int
	flag.IntVar(&workersFlag, "workers", 0, "Number of worker goroutines (default is numCPU - 1)")

	var batchSizeFlag int
	flag.IntVar(&batchSizeFlag, "batchSize", 10000, "Number of passwords per batch")

	var charsetFlag string
	flag.StringVar(&charsetFlag, "charset", "", "Charset to use (default loads from charset.txt if present, else alphanumeric)")

	flag.Parse()

	if mnemonicFlag == "" {
		mnemonicFlag = os.Getenv("BIPBF_MNEMONIC")
		if mnemonicFlag == "" {
			if bytes, err := os.ReadFile("mnemonic.txt"); err == nil {
				mnemonicFlag = string(bytes)
			}
		}
	}

	if addressFlag == "" {
		addressFlag = os.Getenv("BIPBF_ADDRESS")
		if addressFlag == "" {
			if bytes, err := os.ReadFile("address.txt"); err == nil {
				addressFlag = string(bytes)
			}
		}
	}

	if addressTypeFlag == "" {
		addressTypeFlag = os.Getenv("BIPBF_ADDRESS_TYPE")
		if addressTypeFlag == "" {
			if bytes, err := os.ReadFile("addressType.txt"); err == nil {
				addressTypeFlag = string(bytes)
			}
		}
	}

	if mnemonicFlag == "" {
		log.Fatalf("Mnemonic must be specified (via --mnemonic flag, BIPBF_MNEMONIC env variable, or mnemonic.txt)")
	}
	if addressFlag == "" {
		log.Fatalf("Address must be specified (via --address flag, BIPBF_ADDRESS env variable, or address.txt)")
	}
	if addressTypeFlag == "" {
		log.Fatalf("Address type must be specified (via --addressType flag, BIPBF_ADDRESS_TYPE env variable, or addressType.txt)")
	}

	mnemonicFlag = strings.TrimSpace(strings.ToLower(mnemonicFlag))
	addressFlag = strings.TrimSpace(strings.ToLower(addressFlag))
	addressTypeFlag = strings.TrimSpace(strings.ToLower(addressTypeFlag))

	finalCharset := loadCharset(charsetFlag)

	finalWorkers := workersFlag
	if finalWorkers == 0 {
		finalWorkers = runtime.NumCPU() - 1
		if finalWorkers < 1 {
			finalWorkers = 1
		}
	}

	// Connect DB
	db, err := bipbf.InitDB(dbPathFlag)
	if err != nil {
		log.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()

	// Possibly override app_config.max_db_size_mb if --dbSize is given
	if dbSizeGBFlag > 0 {
		if err := setDbSize(db, dbSizeGBFlag*1024); err != nil {
			log.Fatalf("failed to set DB size: %v", err)
		}
	}

	// Build config
	mnemonicHash := bipbf.HashMnemonic(mnemonicFlag)
	cfgID, foundPwd, alreadyFound, err := bipbf.GetOrCreateConfig(db, mnemonicHash, addressFlag, addressTypeFlag)
	if err != nil {
		log.Fatalf("GetOrCreateConfig error: %v", err)
	}
	if alreadyFound {
		log.Printf("Password already found in prior run: %s\n", foundPwd)
		return
	}
	var params map[string]interface{}
	var genType int
	var strategy bipbf.Strategy

	switch modeFlag {
	case "exhaustive":
		params = map[string]interface{}{
			"charset": finalCharset,
			"length":  float64(lenFlag),
		}
		genType = 1
		strategy.CalcTotalPossibilities = exhaustive.CalcTotalPossibilities
		strategy.GenerateNextNStrings = exhaustive.GenerateNextStrings
	default:
		log.Fatalf("Unknown mode: %s. Currently only 'exhaustive' is supported", modeFlag)
	}

	// Convert params to JSON bytes
	paramsBytes, _ := json.Marshal(params)

	gen, err := bipbf.GetOrCreateGeneration(db, cfgID, genType, string(paramsBytes))

	if err != nil {
		log.Fatalf("GetOrCreateGeneration error: %v", err)
	}
	if gen.Done == 1 {
		log.Printf("Generation is already done. Possibly from a prior run.")
		return
	}

	// Prepare runtime args
	runtimeArgs := bipbf.RuntimeArgs{
		NumWorkers: finalWorkers,
		BatchSize:  batchSizeFlag,
	}

	// Run the generic strategy runner with the exhaustive generator
	foundPwd, err = bipbf.RunStrategy(
		db,
		cfgID,
		gen,
		mnemonicFlag,
		addressFlag,
		addressTypeFlag,
		runtimeArgs,
		strategy,
	)
	if err != nil {
		log.Fatalf("RunStrategy error: %v", err)
	}

	// Check final result
	if foundPwd != "" {
		fmt.Printf("Found password: %s\n", foundPwd)
	} else {
		fmt.Println("Password not found in the given range.")
	}
}

// setDbSize updates app_config.max_db_size_mb
func setDbSize(db *sql.DB, sizeMB int) error {
	// Enforce minimum DB size of 0.1GB (100MB)
	if sizeMB < 100 {
		sizeMB = 100
		log.Printf("Warning: Using minimum DB size of 0.1GB (100MB)")
	}
	_, err := db.Exec(`UPDATE app_config SET max_db_size_mb = ?`, sizeMB)
	return err
}

// loadCharset consolidates the charset fallback logic.
func loadCharset(input string) string {
	// Start with the input string (from --charset flag).
	finalCharset := input

	// If not provided via CLI flag, check the environment variable.
	if finalCharset == "" {
		finalCharset = os.Getenv("BIPBF_CHARSET")
	}

	// If still not set, try to load from charset.txt.
	if finalCharset == "" {
		if _, err := os.Stat("charset.txt"); err == nil {
			bytes, err := os.ReadFile("charset.txt")
			if err != nil {
				log.Fatalf("Failed to read charset.txt: %v", err)
			}
			finalCharset = strings.TrimSpace(string(bytes))
		}
	}

	// If no charset is found, use the default charset.
	if finalCharset == "" {
		finalCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ "
	}

	// Sort runes to have a deterministic order.
	runes := []rune(finalCharset)
	sort.Slice(runes, func(i, j int) bool {
		return runes[i] < runes[j]
	})
	return string(runes)
}
