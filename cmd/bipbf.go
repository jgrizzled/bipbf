package main

import (
	"bipbf"
	"bipbf/strats/exhaustive"
	"bipbf/strats/pwlist"
	"bipbf/strats/variation"
	"bipbf/strats/wordlist"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
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

	var dbSizeGBFlag int
	flag.IntVar(&dbSizeGBFlag, "db-size", 0, "Max db size in GB (0 = use default)")

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

	// Add minLen and maxLen flags for exhaustive mode
	var minLenFlag int
	flag.IntVar(&minLenFlag, "min-len", 1, "Minimum length of passwords to brute force (for exhaustive mode)")
	var maxLenFlag int
	flag.IntVar(&maxLenFlag, "max-len", 1, "Maximum length of passwords to brute force (for exhaustive mode)")

	var workersFlag int
	flag.IntVar(&workersFlag, "workers", 0, "Number of worker goroutines (default is numCPU - 1)")

	var batchSizeFlag int
	flag.IntVar(&batchSizeFlag, "batch-size", 10000, "Number of passwords per batch")

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

	// Add clear-pws flag
	var clearPwsFlag bool
	flag.BoolVar(&clearPwsFlag, "clear-pws", false, "Clear the cached passwords and reclaim disk space")

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

	// Possibly override app_config.max_db_size_mb if --dbSize is given
	if dbSizeGBFlag > 0 {
		if err := setDBSize(db, dbSizeGBFlag*1024); err != nil {
			log.Fatalf("failed to set DB size: %v", err)
		}
	}

	// Handle clear-pws flag.  If set, clear passwords and exit.
	if clearPwsFlag {
		if err := bipbf.ClearPasswords(db); err != nil {
			log.Fatalf("ClearPasswords failed: %v", err)
		}
		fmt.Println("Cached passwords cleared.")
		return // Exit after clearing passwords
	}

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

	var bot *bipbf.DiscordBot
	if discordWebhookURLFlag != "" {
		bot = bipbf.NewDiscordBot(discordWebhookURLFlag)
	}

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
			logMsg := fmt.Sprintf("Running exhaustive mode with length %d", currentLen)
			log.Print(logMsg)
			if bot != nil {
				if err := bot.SendMessage(logMsg); err != nil {
					log.Printf("Error sending Discord message: %v", err)
				}
			}
			if !runStrategyForParams(db, config, 1, params, strategy, mnemonicFlag, runtimeArgs, bot) {
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

		// Hash the password file
		pwFileHash, err := hashFile(pwFileFlag)
		if err != nil {
			log.Fatalf("Error hashing password file: %v", err)
		}

		params := map[string]interface{}{
			"pwfile": pwFileFlag,
			"hash":   pwFileHash, // Add the hash to the params
		}
		strategy, err := pwlist.NewStrategy(params)
		if err != nil {
			log.Fatalf("Error creating pwlist strategy: %v", err)
		}
		log.Printf("Running pwlist mode with password file %s", pwFileFlag)
		if !runStrategyForParams(db, config, 2, params, strategy, mnemonicFlag, runtimeArgs, bot) {
			return
		}

	case "variation":
		basePasswords := []string{}

		// Check if basePasswordFlag is set.  If not, try to read from passwords.txt
		if basePasswordFlag != "" {
			basePasswords = append(basePasswords, basePasswordFlag)
		} else {
			if _, err := os.Stat("passwords.txt"); err == nil {
				passwordBytes, err := os.ReadFile("passwords.txt")
				if err != nil {
					log.Fatalf("Failed to read passwords.txt: %v", err)
				}
				passwordLines := strings.Split(string(passwordBytes), "\n")
				for _, line := range passwordLines {
					trimmedLine := strings.TrimSpace(line)
					if trimmedLine != "" {
						basePasswords = append(basePasswords, trimmedLine)
					}
				}
			} else {
				log.Fatalf("Must specify --base or provide a passwords.txt file for variation mode")
			}
		}
		log.Printf("Running variation mode with %d base passwords", len(basePasswords))
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
			logMsg := fmt.Sprintf("Running variation mode with base password %s***", basePassword[:displayLen])
			log.Print(logMsg)
			if bot != nil {
				if err := bot.SendMessage(logMsg); err != nil {
					log.Printf("Error sending Discord message: %v", err)
				}
			}
			if !runStrategyForParams(db, config, 3, params, strategy, mnemonicFlag, runtimeArgs, bot) {
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
		wordlistBytes, err := os.ReadFile(wordlistFileFlag)
		if err != nil {
			log.Fatalf("Failed to read wordlist file: %v", err)
		}
		wordlistLines := strings.Split(string(wordlistBytes), "\n")

		// Trim whitespace and lowercase, and remove empty lines
		var words []string
		for _, line := range wordlistLines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				words = append(words, strings.ToLower(trimmed))
			}
		}

		// Sort the words alphabetically
		sort.Strings(words)

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
		logMsg := fmt.Sprintf("Running wordlist mode with %d words, length %d, and separator %s", len(words), lenFlag, wordlistSeparatorFlag)
		log.Print(logMsg)
		if bot != nil {
			if err := bot.SendMessage(logMsg); err != nil {
				log.Printf("Error sending Discord message: %v", err)
			}
		}
		if !runStrategyForParams(db, config, 4, params, strategy, mnemonicFlag, runtimeArgs, bot) {
			return
		}

	default:
		log.Fatalf("Unknown mode: %s. Supported modes are 'exhaustive', 'pwlist', 'variation', and 'wordlist'.", modeFlag)
	}
}

// runStrategyForParams executes a strategy and returns true if the password was NOT found
func runStrategyForParams(db *sql.DB, config *bipbf.Config, genType int, params map[string]interface{}, strategy bipbf.Strategy, mnemonicFlag string, runtimeArgs bipbf.RuntimeArgs, discordBot *bipbf.DiscordBot) bool {
	// Convert params to JSON bytes
	paramsBytes, _ := json.Marshal(params)

	gen, err := bipbf.GetOrCreateGeneration(db, config.ID, genType, string(paramsBytes))
	if err != nil {
		log.Fatalf("GetOrCreateGeneration error: %v", err)
	}
	if gen.Done == 1 {
		log.Printf("Generation is already done. Possibly from a prior run.")
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
	)
	if err != nil {
		log.Fatalf("RunStrategy error: %v", err)
	}

	// Check final result
	if foundPwd != "" {
		fmt.Printf("Found password: %s\n", foundPwd)

		if discordBot != nil {
			message := fmt.Sprintf("Password found: %s", foundPwd)
			if err := discordBot.SendMessage(message); err != nil {
				log.Printf("Error sending Discord message: %v", err)
			}
		}

		// Clean up all cached passwords for this config ID
		if _, err := db.Exec(`DELETE FROM password WHERE config_id = ?`, config.ID); err != nil {
			log.Printf("Warning: Failed to delete passwords for config_id %d: %v", config.ID, err)
		}

		return false // Indicate password *was* found
	} else {
		fmt.Println("Password not found with these parameters.")
		return true // Indicate password not found
	}
}

// setDBSize updates app_config.max_db_size_mb
func setDBSize(db *sql.DB, sizeMB int) error {
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

// hashFile calculates the SHA256 hash of a file.
func hashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
