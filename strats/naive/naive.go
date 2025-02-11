package naive

import (
	"bipbf"
	"bipbf/bip39"
	"database/sql"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	go_bip39 "github.com/tyler-smith/go-bip39"
)

// workerResult holds the result of hashing an entire batch.
// We track batchNumber to handle out-of-order completion.
type workerResult struct {
	batchNumber   int
	lastPassword  string
	foundPassword *string
	rowId         int
	length        int
}

// batchItem holds the data for a single batch to be processed.
type batchItem struct {
	batchNumber int
	passwords   []string
	rowId       int
	length      int
}

// BruteForceConfig holds all configuration for a brute force run
type BruteForceConfig struct {
	Charset     string
	Workers     int
	BatchSize   int
	MinLen      int
	MaxLen      int
	Mnemonic    string
	Address     string
	AddressType string // "btc-nativesegwit" or "eth"
}

// BruteForceResult holds the result of a brute force attempt
type BruteForceResult struct {
	FoundPassword string
	Found         bool
}

// NaiveBruteForce performs the naive brute force search with the given configuration.
func NaiveBruteForce(db *sql.DB, config BruteForceConfig) (BruteForceResult, error) {
	address := strings.ToLower(config.Address)
	mnemonic := strings.ToLower(config.Mnemonic)
	if !go_bip39.IsMnemonicValid(mnemonic) {
		return BruteForceResult{}, fmt.Errorf("invalid mnemonic: %s", mnemonic)
	}
	if len(address) == 0 {
		return BruteForceResult{}, fmt.Errorf("address cannot be empty")
	}
	if len(config.Charset) == 0 {
		return BruteForceResult{}, fmt.Errorf("charset cannot be empty")
	}
	if len(config.AddressType) == 0 {
		return BruteForceResult{}, fmt.Errorf("addressType cannot be empty")
	}
	// Check existing found password
	existingPassword, foundAlready, err := bipbf.GetExistingFoundPassword(
		db,
		config.Charset,
		mnemonic,
		address,
		config.AddressType,
	)
	if err != nil {
		return BruteForceResult{}, fmt.Errorf("DB error checking existing found password: %v", err)
	}
	if foundAlready {
		return BruteForceResult{FoundPassword: existingPassword, Found: true}, nil
	}

	foundPassword := ""
	var wg sync.WaitGroup

	// Channel to communicate found string from aggregator to main loop
	foundPasswordCh := make(chan string, 1)

	// Channel to send batchItem structs to workers
	batchChan := make(chan *batchItem, config.Workers*10)

	// Channel to send workerResult structs to aggregator
	resultChan := make(chan workerResult, config.Workers)

	// Separate stop channels for different goroutines
	stopWorkers := make(chan struct{})
	stopAggregator := make(chan struct{})
	stopProducer := make(chan struct{})

	// Signal that the batchProducer has finished producing all possible strings
	producerDone := make(chan struct{})

	// Add WaitGroup counts for all goroutines up front
	wg.Add(config.Workers + 2) // workers + producer + aggregator

	//
	// AGGREGATOR GOROUTINE
	//
	go func() {
		defer wg.Done()
		found := false
		expectedBatch := 1
		pending := make(map[int]workerResult)

		// Initialize timing variables and batch tracking
		startTime := time.Now()
		lastPrintTime := startTime
		lastDBUpdate := startTime

		// Track last 100 batches timing including lastProcessed password
		type batchTiming struct {
			batchNum     int
			time         time.Time
			lastPassword string
		}
		recentBatches := make([]batchTiming, 0, 100)
		var currentLength int // holds the current length being processed

		for {
			select {
			case <-stopAggregator:
				return
			case res, ok := <-resultChan:
				if !ok {
					if !found {
						foundPasswordCh <- ""
					}
					return
				}

				// If the length has changed, update and reset recentBatches
				if currentLength != res.length {
					currentLength = res.length
					recentBatches = recentBatches[:0]
				}

				// Handle found password first, before checking further logic
				if !found && res.foundPassword != nil {
					found = true
					_, err := db.Exec(`
						UPDATE naive_run
						SET found_password = ?, done = 1
						WHERE id = ?
					`, *res.foundPassword, res.rowId)
					if err != nil {
						log.Printf("Error updating found_password: %v", err)
					}
					foundPasswordCh <- *res.foundPassword
					return // Exit immediately after finding password
				}

				// Track batch timing with the last processed password
				recentBatches = append(recentBatches, batchTiming{
					batchNum:     res.batchNumber,
					time:         time.Now(),
					lastPassword: res.lastPassword,
				})
				if len(recentBatches) > 100 {
					recentBatches = recentBatches[1:]
				}

				// Log average passwords per second and ETA every 30 seconds
				now := time.Now()
				if now.Sub(lastPrintTime) >= 30*time.Second && len(recentBatches) > 0 {
					oldestBatch := recentBatches[0]
					newestBatch := recentBatches[len(recentBatches)-1]
					batchesProcessed := newestBatch.batchNum - oldestBatch.batchNum + 1
					timeSpan := newestBatch.time.Sub(oldestBatch.time).Seconds()
					if timeSpan > 0 {
						passwordsPerSecond := float64(batchesProcessed*config.BatchSize) / timeSpan
						// Compute ETA and percentage completion
						processedIndex := stringToIndex(newestBatch.lastPassword, currentLength, config.Charset)
						if processedIndex >= 0 {
							totalPossibilities := math.Pow(float64(len(config.Charset)), float64(currentLength))
							remaining := totalPossibilities - float64(processedIndex) - 1
							percentComplete := (float64(processedIndex) + 1) / totalPossibilities * 100
							var eta time.Duration
							if passwordsPerSecond > 0 {
								etaSeconds := remaining / passwordsPerSecond
								eta = time.Duration(etaSeconds * float64(time.Second))
							} else {
								eta = 0
							}
							log.Printf("Length: %d, PPS: %.2f, Progress: %.2f%%, ETA: %s",
								currentLength, passwordsPerSecond, percentComplete, eta)
						}
					}
					lastPrintTime = now
				}

				// Throttle DB update for last_processed_pw to every 5 seconds
				pending[res.batchNumber] = res
				if time.Since(lastDBUpdate) >= 5*time.Second {
					var lastProcessed string
					var updateRowId int
					for {
						r, exists := pending[expectedBatch]
						if !exists {
							break
						}
						lastProcessed = r.lastPassword
						updateRowId = r.rowId
						delete(pending, expectedBatch)
						expectedBatch++
					}
					if lastProcessed != "" {
						if _, err := db.Exec(`
							UPDATE naive_run
							SET last_processed_pw = ?
							WHERE id = ?
						`, lastProcessed, updateRowId); err != nil {
							log.Printf("Error updating last_processed_pw: %v", err)
						}
					}
					lastDBUpdate = time.Now()
				}
			}
		}
	}()

	// Before the worker goroutine loop, add a new waitgroup for workers:
	var workerWg sync.WaitGroup

	//
	// WORKER GOROUTINES
	//
	for i := 0; i < config.Workers; i++ {
		workerWg.Add(1)
		go func() {
			defer wg.Done()
			defer workerWg.Done()
			for {
				select {
				case <-stopWorkers:
					return
				case batch, ok := <-batchChan:
					if !ok {
						return
					}
					res := processBatch(batch, mnemonic, address, config.AddressType)
					// Check cancellation before sending the result
					select {
					case <-stopWorkers:
						return
					case resultChan <- res:
						// result sent
					}
				}
			}
		}()
	}

	// NEW: Launch a goroutine to close resultChan after all workers have finished.
	go func() {
		workerWg.Wait()
		close(resultChan)
	}()

	//
	// BATCH PRODUCER GOROUTINE
	//
	go func() {
		defer wg.Done()
		defer close(producerDone)
		batchNumber := 0

	outerLoop:
		for length := config.MinLen; length <= config.MaxLen; length++ {
			select {
			case <-stopProducer:
				break outerLoop
			default:
			}

			naiveRow, err := bipbf.GetOrCreateNaiveRun(db, config.Charset, length, mnemonic, address, config.AddressType)
			if err != nil {
				log.Fatalf("Failed to get/create naive run row: %v", err)
			}

			if naiveRow.FoundPassword != nil {
				log.Printf("Length %d row already has found_str: %s\n", length, *naiveRow.FoundPassword)
				// We already have a found password in DB; let aggregator/main know
				foundPasswordCh <- *naiveRow.FoundPassword
				break outerLoop
			}
			if naiveRow.Done == 1 {
				// Already done for this length; skip
				continue
			}

			currentStr := naiveRow.LastProcessedPw
			if currentStr == "" {
				log.Printf("No last processed password found; starting length %d from beginning", length)
			} else {
				log.Printf("Resuming from last processed password for length %d: %s", length, currentStr)
			}

			// Produce batches for this length
			for {
				select {
				case <-stopProducer:
					break outerLoop
				default:
				}

				batchNumber++
				strs, nextStr := generateNextNStrings(currentStr, config.Charset, config.BatchSize, length)
				if len(strs) == 0 {
					break
				}
				batchChan <- &batchItem{
					batchNumber: batchNumber,
					passwords:   strs,
					rowId:       naiveRow.ID,
					length:      length,
				}
				if nextStr == "" {
					break
				}
				currentStr = nextStr
			}

			// Mark done for this length
			if _, err := db.Exec(`
				UPDATE naive_run
				SET done = 1
				WHERE id = ?
			`, naiveRow.ID); err != nil {
				log.Printf("Failed to mark done for row ID=%d: %v", naiveRow.ID, err)
			}
		}
		// No more batches to produce
		close(batchChan)
	}()

	// wait for found password
	foundPassword = <-foundPasswordCh
	// Close all stop channels
	close(stopWorkers)
	close(stopAggregator)
	close(stopProducer)
	// Drain the batch channel to prevent producer goroutine from blocking
	go func() {
		for range batchChan {
			// Drain remaining batches
		}
	}()

	wg.Wait()

	// Finally, see if we got a found password
	if foundPassword != "" {
		return BruteForceResult{FoundPassword: foundPassword, Found: true}, nil
	}
	return BruteForceResult{Found: false}, nil
}

// processBatch derives the address for each password in the batch.
// If the correct address is found, we store the foundPassword in workerResult.foundPassword.
func processBatch(batch *batchItem, mnemonic, address, addressType string) workerResult {
	// Check for empty batch
	if len(batch.passwords) == 0 {
		return workerResult{
			batchNumber:   batch.batchNumber,
			lastPassword:  "",
			foundPassword: nil,
			rowId:         batch.rowId,
			length:        batch.length,
		}
	}

	last := batch.passwords[len(batch.passwords)-1]
	var found *string

	// Process each password in the batch
	for _, password := range batch.passwords {
		var derivedAddress string
		var err error

		switch addressType {
		case "btc-nativesegwit":
			addr, err := bip39.GetAddressFromMnemonic(mnemonic, password, 0, true, 0)
			if err != nil {
				continue // Skip invalid passwords
			}
			derivedAddress = addr.EncodeAddress()
		case "eth":
			derivedAddress, err = bip39.GetEthereumAddressFromMnemonic(mnemonic, password, 0)
			if err != nil {
				continue // Skip invalid passwords
			}
		}

		// Case-insensitive comparison for addresses
		if strings.EqualFold(derivedAddress, address) {
			password := password // Create a new variable to avoid closure issues
			found = &password
			break
		}
	}

	return workerResult{
		batchNumber:   batch.batchNumber,
		lastPassword:  last,
		foundPassword: found,
		rowId:         batch.rowId,
		length:        batch.length,
	}
}
