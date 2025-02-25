package main

import (
	"bipbf"
	"bipbf/strats/exhaustive"
	"bipbf/strats/pwlist"
	"bipbf/strats/variation"
	"bipbf/strats/wordlist"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/tidwall/shardmap"
)

func main() {
	// Load environment variables from .env file, if it exists.
	if err := godotenv.Load(); err != nil {
		// Don't log "file not found" errors, as it's okay if .env is absent.
		if _, ok := err.(*os.PathError); !ok {
			log.Printf("Error loading .env file: %v", err)
		}
	}

	var dbPathFlag string
	flag.StringVar(&dbPathFlag, "db-path", "db.sqlite", "Path to SQLite database file")

	var modeFlag string
	flag.StringVar(&modeFlag, "mode", "", "exhaustive, pwlist, variation, or wordlist")

	var mnemonicFlag string
	flag.StringVar(&mnemonicFlag, "mnemonic", "", "Mnemonic to test passwords against (not stored in DB)")

	var addressFlag string
	flag.StringVar(&addressFlag, "address", "", "Address to find")

	var addressTypeFlag string
	flag.StringVar(&addressTypeFlag, "address-type", "", "Address type: 'btc-bech32' or 'eth'")

	var lenFlag int
	flag.IntVar(&lenFlag, "len", 0, "Length of passwords to brute force")

	var minLenFlag int
	flag.IntVar(&minLenFlag, "min-len", 1, "Minimum length of passwords to brute force (for exhaustive mode)")
	var maxLenFlag int
	flag.IntVar(&maxLenFlag, "max-len", 1, "Maximum length of passwords to brute force (for exhaustive mode)")

	var workersFlag int
	flag.IntVar(&workersFlag, "workers", 0, "Number of worker goroutines (default is numCPU - 1)")

	var batchSizeFlag int
	flag.IntVar(&batchSizeFlag, "batch-size", 100000, "Number of passwords per batch")

	var cacheSizeGBFlag float64
	flag.Float64Var(&cacheSizeGBFlag, "cache-size", 1.0, "Maximum cache size in GB (default 1 GB)")

	var charsetFlag string
	flag.StringVar(&charsetFlag, "charset", "", "Charset to use (default loads from charset.txt if present, else alphanumeric + symbols)")

	// pwlist specific flags
	var pwFileFlag string
	flag.StringVar(&pwFileFlag, "pwfile", "", "Path to password file (required for pwlist mode)")

	// variation specific flags
	var basePasswordFlag string
	flag.StringVar(&basePasswordFlag, "base", "", "Base password to vary (for variation mode), overrides passwords.txt")
	var variationOpsFlag int
	flag.IntVar(&variationOpsFlag, "ops", 1, "Number of variation operations (for variation mode)")

	// wordlist specific flags
	var wordlistFileFlag string
	flag.StringVar(&wordlistFileFlag, "wordlist-file", "", "Path to wordlist file (for wordlist mode)")
	var wordlistSeparatorFlag string
	flag.StringVar(&wordlistSeparatorFlag, "separator", "", "Separator for wordlist mode (defaults to empty string)")

	// Flags for account and address start/end
	var accountStartFlag int
	flag.IntVar(&accountStartFlag, "account-start", 0, "Account start index (default 0)")
	var accountEndFlag int
	flag.IntVar(&accountEndFlag, "account-end", 0, "Account end index (default 0)")
	var addressStartFlag int
	flag.IntVar(&addressStartFlag, "address-start", 0, "Address start index (default 0)")
	var addressEndFlag int
	flag.IntVar(&addressEndFlag, "address-end", 0, "Address end index (default 0)")

	// Flags for Discord webhook URL
	var discordWebhookURLFlag string
	flag.StringVar(&discordWebhookURLFlag, "discord-url", "", "Discord webhook URL")

	var resetProgressFlag bool
	flag.BoolVar(&resetProgressFlag, "reset-progress", false, "Reset progress for this run (deletes the generation record)")

	flag.Parse()

	// Load mnemonic, address, and addressType in order of precedence:
	// 1. Flag
	// 2. Environment variable
	// 3. File

	if mnemonicFlag == "" {
		mnemonicFlag = os.Getenv("BIPBF_MNEMONIC")
	}

	if addressFlag == "" {
		addressFlag = os.Getenv("BIPBF_ADDRESS")
	}

	if addressTypeFlag == "" {
		addressTypeFlag = os.Getenv("BIPBF_ADDRESS_TYPE")
	}

	// Load account and address indices from environment variables if flags are not set
	if accountStartFlag == 0 {
		if envVal := os.Getenv("BIPBF_ACCOUNT_START"); envVal != "" {
			if val, err := strconv.Atoi(envVal); err == nil {
				accountStartFlag = val
			}
		}
	}

	if accountEndFlag == 0 {
		if envVal := os.Getenv("BIPBF_ACCOUNT_END"); envVal != "" {
			if val, err := strconv.Atoi(envVal); err == nil {
				accountEndFlag = val
			}
		}
	}

	if addressStartFlag == 0 {
		if envVal := os.Getenv("BIPBF_ADDRESS_START"); envVal != "" {
			if val, err := strconv.Atoi(envVal); err == nil {
				addressStartFlag = val
			}
		}
	}

	if addressEndFlag == 0 {
		if envVal := os.Getenv("BIPBF_ADDRESS_END"); envVal != "" {
			if val, err := strconv.Atoi(envVal); err == nil {
				addressEndFlag = val
			}
		}
	}

	// Load Discord webhook URL from flag or environment variable
	if discordWebhookURLFlag == "" {
		discordWebhookURLFlag = os.Getenv("BIPBF_DISCORD_URL")
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

	if mnemonicFlag == "" {
		log.Fatalf("Mnemonic must be specified (via --mnemonic flag or BIPBF_MNEMONIC env variable)")
	}
	if addressFlag == "" {
		log.Fatalf("Address must be specified (via --address flag or BIPBF_ADDRESS env variable)")
	}
	if addressTypeFlag == "" {
		log.Fatalf("Address type must be specified (via --address-type flag or BIPBF_ADDRESS_TYPE env variable)")
	}

	// Build config
	mnemonicHash := bipbf.HashMnemonic(mnemonicFlag)
	config, foundPwd, err := bipbf.GetOrCreateConfig(db, mnemonicHash, addressFlag, addressTypeFlag, accountStartFlag, accountEndFlag, addressStartFlag, addressEndFlag)
	if err != nil {
		log.Fatalf("GetOrCreateConfig error: %v", err)
	}
	if foundPwd {
		log.Printf("Password already found in prior run: %s\n", config.FoundPassword.String)
		return
	}

	// Prepare runtime args (common to all strategies)
	runtimeArgs := bipbf.RuntimeArgs{
		NumWorkers: finalWorkers,
		BatchSize:  batchSizeFlag,
	}

	// Calculate max cache length based on cache size in GB
	// Assuming each password is 32 characters and each character is 1 byte
	// Plus overhead for map storage (conservative estimate)
	const assumedPasswordBytes = 32
	const mapOverheadBytes = 16 // Conservative estimate for map overhead per entry
	const bytesPerGB = 1024 * 1024 * 1024
	maxCacheEntries := int(cacheSizeGBFlag * bytesPerGB / (assumedPasswordBytes + mapOverheadBytes))
	runtimeArgs.MaxCacheLen = maxCacheEntries

	// By default, cache is disabled
	runtimeArgs.CacheEnabled = false

	var bot *bipbf.DiscordBot
	if discordWebhookURLFlag != "" {
		bot = bipbf.NewDiscordBot(discordWebhookURLFlag)
	}
	var cache shardmap.Map
	// --- Strategy Selection and Execution ---
	switch modeFlag {
	case "exhaustive":
		// If lenFlag is used, treat it as both min and max
		if lenFlag != 0 {
			minLenFlag = lenFlag
			maxLenFlag = lenFlag
		}

		if minLenFlag > maxLenFlag {
			log.Fatalf("--min-len cannot be greater than --max-len")
		}

		log.Printf("Running exhaustive mode with lengths %d to %d", minLenFlag, maxLenFlag)

		// Iterate through lengths
		for currentLen := minLenFlag; currentLen <= maxLenFlag; currentLen++ {
			params := map[string]interface{}{
				"charset": finalCharset,
				"length":  float64(currentLen),
			}
			strategy, err := exhaustive.NewStrategy(params)
			if err != nil {
				log.Fatalf("Error creating exhaustive strategy: %v", err)
			}
			log.Printf("Running exhaustive mode with length %d", currentLen)
			if !runStrategyForParams(db, config, 1, params, strategy, mnemonicFlag, runtimeArgs, bot, resetProgressFlag, &cache) {
				return // Exit if password found
			}
		}

	case "pwlist":
		if pwFileFlag == "" {
			// Try to read from passwords.txt if pwfile is not specified
			if _, err := os.Stat("passwords.txt"); err == nil {
				pwFileFlag = "passwords.txt"
			} else {
				log.Fatalf("pwfile flag is required for pwlist mode, or a passwords.txt file must exist")
			}
		}

		// Load passwords from file
		passwords, err := loadUniqueLines(pwFileFlag, nil)
		if err != nil {
			log.Fatalf("Failed to load passwords: %v", err)
		}

		// Convert passwords to []interface{}
		var pwlistInterface []interface{}
		for _, pw := range passwords {
			pwlistInterface = append(pwlistInterface, pw)
		}

		params := map[string]interface{}{
			"pwlist": pwlistInterface,
		}
		strategy, err := pwlist.NewStrategy(params)
		if err != nil {
			log.Fatalf("Error creating pwlist strategy: %v", err)
		}
		log.Printf("Running pwlist mode with %d passwords from %s", len(passwords), pwFileFlag)
		if !runStrategyForParams(db, config, 2, params, strategy, mnemonicFlag, runtimeArgs, bot, resetProgressFlag, &cache) {
			return
		}

	case "variation":
		var basePasswords []string

		// First check if basePasswordFlag is set
		if basePasswordFlag != "" {
			basePasswords = []string{basePasswordFlag}
		} else {
			// Try to read from pwfile or passwords.txt
			pwFile := pwFileFlag
			if pwFile == "" {
				// Check if passwords.txt exists as fallback
				if _, err := os.Stat("passwords.txt"); err == nil {
					pwFile = "passwords.txt"
				} else {
					log.Fatalf("Must specify --base, --pwfile, or provide a passwords.txt file for variation mode")
				}
			}

			var err error
			basePasswords, err = loadUniqueLines(pwFile, nil)
			if err != nil {
				log.Fatalf("Failed to load passwords: %v", err)
			}
		}

		log.Printf("Running variation mode with %d base passwords", len(basePasswords))

		// Enable cache for variation mode
		runtimeArgs.CacheEnabled = true

		// Iterate through base passwords
		for _, basePassword := range basePasswords {
			params := map[string]interface{}{
				"base_password": basePassword,
				"charset":       finalCharset,
				"operations":    float64(variationOpsFlag),
			}
			strategy, err := variation.NewStrategy(params)
			if err != nil {
				log.Fatalf("Error creating variation strategy: %v", err)
			}
			displayLen := 3
			if len(basePassword) < displayLen {
				displayLen = len(basePassword)
			}
			log.Printf("Running variation mode with base password %s***", basePassword[:displayLen])
			if !runStrategyForParams(db, config, 3, params, strategy, mnemonicFlag, runtimeArgs, bot, resetProgressFlag, &cache) {
				return
			}
		}

	case "wordlist":
		if wordlistFileFlag == "" {
			// Try to read from wordlist.txt if wordlist flag is not specified
			if _, err := os.Stat("wordlist.txt"); err == nil {
				wordlistFileFlag = "wordlist.txt"
			} else {
				log.Fatalf("wordlist flag is required for wordlist mode, or a wordlist.txt file must exist")
			}
		}

		// Read in the wordlist from file
		words, err := loadUniqueLines(wordlistFileFlag, strings.ToLower)
		if err != nil {
			log.Fatalf("Failed to load wordlist: %v", err)
		}

		var wordsInterface []interface{}
		for _, word := range words {
			wordsInterface = append(wordsInterface, word)
		}

		params := map[string]interface{}{
			"wordlist":  wordsInterface,
			"length":    float64(lenFlag),
			"separator": wordlistSeparatorFlag,
		}

		strategy, err := wordlist.NewStrategy(params)
		if err != nil {
			log.Fatalf("Error creating wordlist strategy: %v", err)
		}
		log.Printf("Running wordlist mode with %d words, length %d, and separator %s", len(words), lenFlag, wordlistSeparatorFlag)
		if !runStrategyForParams(db, config, 4, params, strategy, mnemonicFlag, runtimeArgs, bot, resetProgressFlag, &cache) {
			return
		}

	default:
		log.Fatalf("Unknown mode: %s. Supported modes are 'exhaustive', 'pwlist', 'variation', and 'wordlist'.", modeFlag)
	}
	logMsg := "Password not found with these parameters."
	log.Print(logMsg)
	if bot != nil {
		if err := bot.SendMessage(logMsg); err != nil {
			log.Printf("Error sending Discord message: %v", err)
		}
	}
}

// runStrategyForParams executes a strategy and returns true if the password was NOT found
func runStrategyForParams(db *sql.DB, config *bipbf.Config, genType int, params map[string]interface{}, strategy bipbf.Strategy, mnemonicFlag string, runtimeArgs bipbf.RuntimeArgs, discordBot *bipbf.DiscordBot, resetProgress bool, cache *shardmap.Map) bool {
	// Convert params to JSON bytes
	paramsBytes, _ := json.Marshal(params)

	gen, err := bipbf.GetOrCreateGeneration(db, config.ID, genType, string(paramsBytes))
	if err != nil {
		log.Fatalf("GetOrCreateGeneration error: %v", err)
	}
	if resetProgress {
		if err := bipbf.DeleteGeneration(db, gen.ID); err != nil {
			log.Fatalf("Failed to delete generation: %v", err)
		}
		// Get a fresh generation
		gen, err = bipbf.GetOrCreateGeneration(db, config.ID, genType, string(paramsBytes))
		if err != nil {
			log.Fatalf("GetOrCreateGeneration error after reset: %v", err)
		}
	}
	if gen.Done == 1 {
		log.Printf("Generation already completed in a prior run.")
		return true // Indicate password not found (generation already done)
	}

	foundPwd, err := bipbf.RunStrategy(
		db,
		config,
		gen,
		mnemonicFlag,
		runtimeArgs,
		strategy,
		discordBot,
		cache,
	)
	if err != nil {
		log.Fatalf("RunStrategy error: %v", err)
	}

	// Check final result
	if foundPwd != "" {
		logMsg := fmt.Sprintf("Found password: %s", foundPwd)
		log.Print(logMsg)

		if discordBot != nil {
			if err := discordBot.SendMessage(logMsg); err != nil {
				log.Printf("Error sending Discord message: %v", err)
			}
		}

		return false // Indicate password *was* found
	} else {
		return true // Indicate password not found
	}
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

	// Remove duplicates
	seen := make(map[rune]bool)
	var unique []rune
	for _, r := range finalCharset {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}

	// Sort runes to have a deterministic order
	sort.Slice(unique, func(i, j int) bool {
		return unique[i] < unique[j]
	})
	return string(unique)
}

// loadUniqueLines reads lines from a file, trims whitespace, removes empty lines and duplicates
func loadUniqueLines(filePath string, transform func(string) string) ([]string, error) {
	// Read file
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}

	// Use map to track unique lines
	uniqueLines := make(map[string]bool)

	// Process each line
	for _, line := range strings.Split(string(fileBytes), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			if transform != nil {
				trimmed = transform(trimmed)
			}
			uniqueLines[trimmed] = true
		}
	}

	// Convert map keys to sorted slice
	var lines []string
	for line := range uniqueLines {
		lines = append(lines, line)
	}
	sort.Strings(lines)

	return lines, nil
}
