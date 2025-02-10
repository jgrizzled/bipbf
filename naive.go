package bipbf

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"bipbf/bip"
)

// workerResult holds the result of hashing an entire batch.
// We track batchNumber to handle out-of-order completion.
type workerResult struct {
	batchNumber    int
	lastPassword   string
	foundPassword  *string
	possibleResume string
	rowId          int
}

// batchItem holds the data for a single batch to be processed.
type batchItem struct {
	batchNumber int
	passwords   []string
	rowId       int
}

// BruteForceConfig holds all configuration for a brute force run
type BruteForceConfig struct {
	Charset     string
	Workers     int
	BatchSize   int
	MinLen      int
	MaxLen      int
	DbPath      string
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
// Refactored so that batch generation happens in a separate goroutine (batchProducer).
func NaiveBruteForce(config BruteForceConfig) (BruteForceResult, error) {
	db, err := initDB(config.DbPath)
	if err != nil {
		return BruteForceResult{}, fmt.Errorf("failed to init DB: %v", err)
	}
	defer db.Close()

	// Check existing found password
	existingPassword, foundAlready, err := getExistingFoundPassword(
		db,
		config.Charset,
		config.Mnemonic,
		config.Address,
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
	batchChan := make(chan batchItem, config.Workers*2)

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

		// Track last 1000 batches timing
		type batchTiming struct {
			batchNum int
			time     time.Time
		}
		recentBatches := make([]batchTiming, 0, 1000)

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

				// Track batch timing
				recentBatches = append(recentBatches, batchTiming{
					batchNum: res.batchNumber,
					time:     time.Now(),
				})
				// Keep only last 1000 batches
				if len(recentBatches) > 1000 {
					recentBatches = recentBatches[1:]
				}

				// Log average passwords per second every 30 seconds
				now := time.Now()
				if now.Sub(lastPrintTime) >= 30*time.Second && len(recentBatches) > 0 {
					// Calculate rate based on recent batches
					oldestBatch := recentBatches[0]
					newestBatch := recentBatches[len(recentBatches)-1]
					batchesProcessed := newestBatch.batchNum - oldestBatch.batchNum + 1
					timeSpan := newestBatch.time.Sub(oldestBatch.time).Seconds()
					if timeSpan > 0 {
						passwordsPerSecond := float64(batchesProcessed*config.BatchSize) / timeSpan
						log.Printf("Recent average passwords per second (last %d batches): %.2f",
							len(recentBatches), passwordsPerSecond)
					}
					lastPrintTime = now
				}

				// Handle in-order logic for last_processed_pw
				pending[res.batchNumber] = res
				for {
					r, exists := pending[expectedBatch]
					if !exists {
						break
					}
					if _, err := db.Exec(`
						UPDATE naive_run
						SET last_processed_pw = ?
						WHERE id = ?
					`, r.lastPassword, r.rowId); err != nil {
						log.Printf("Error updating last_processed_pw: %v", err)
					}
					delete(pending, expectedBatch)
					expectedBatch++
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
					res := processBatch(batch, config.Mnemonic, config.Address, config.AddressType)
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

			naiveRow, err := getOrCreateNaiveRun(db, config.Charset, length, config.Mnemonic, config.Address, config.AddressType)
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

			currentStr := naiveRow.LastProcessedStr

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
				batchChan <- batchItem{
					batchNumber: batchNumber,
					passwords:   strs,
					rowId:       naiveRow.ID,
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
	select {
	case fs := <-foundPasswordCh:
		foundPassword = fs
	}
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

	// Finally, see if we got a found string
	if foundPassword != "" {
		return BruteForceResult{FoundPassword: foundPassword, Found: true}, nil
	}
	return BruteForceResult{Found: false}, nil
}

// processBatch hashes each string in the batch, compares against findHash, returns workerResult.
// If found, we store the foundString in workerResult.foundString.
func processBatch(batch batchItem, mnemonic, address, addressType string) workerResult {
	// Check for empty batch
	if len(batch.passwords) == 0 {
		return workerResult{
			batchNumber:    batch.batchNumber,
			lastPassword:   "",
			foundPassword:  nil,
			possibleResume: "",
			rowId:          batch.rowId,
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
			addr, err := bip.GetAddressFromMnemonic(mnemonic, password, 0, true, 0)
			if err != nil {
				continue // Skip invalid passwords
			}
			derivedAddress = addr.EncodeAddress()
		case "eth":
			derivedAddress, err = bip.GetEthereumAddressFromMnemonic(mnemonic, password)
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
		batchNumber:    batch.batchNumber,
		lastPassword:   last,
		foundPassword:  found,
		possibleResume: "",
		rowId:          batch.rowId,
	}
}
