package bipbf

import (
	"log"
	"strings"
	"time"
)

type workerResult struct {
	batchNumber        int
	foundPassword *string
	passwords          []string
	progress           string
}

type batchItem struct {
	batchNumber int
	passwords   []string
	progress    string
}


// worker processes each batch by deriving addresses and checking if any match.
func worker(
	mnemonic string,
	config *Config,
	batchChan <-chan batchItem,
	resultChan chan<- workerResult,
	stopChan <-chan struct{},
) {
	const waitThreshold = 10 * time.Millisecond // Threshold for logging if waited too long
	const logAfterCount = 10                    // Number of waits before logging

	var batchWaitCount int
	var resultWaitCount int

	for {
		// Measure wait time when receiving from batchChan
		startBatch := time.Now()
		var batch batchItem
		var ok bool
		select {
		case <-stopChan:
			return
		case batch, ok = <-batchChan:
			// received batch, continue processing
		}
		elapsedBatch := time.Since(startBatch)
		if elapsedBatch > waitThreshold {
			batchWaitCount++
			if batchWaitCount >= logAfterCount {
				log.Printf("runWorker: waited >%v for batchChan %d times", waitThreshold, batchWaitCount)
				batchWaitCount = 0 // Reset counter
			}
		}
		if !ok {
			return
		}

		res := processBatch(batch, mnemonic, config)

		// Measure wait time when sending to resultChan
		startResult := time.Now()
		select {
		case resultChan <- res:
			elapsedResult := time.Since(startResult)
			if elapsedResult > waitThreshold {
				resultWaitCount++
				if resultWaitCount >= logAfterCount {
					log.Printf("runWorker: waited >%v for resultChan %d times", waitThreshold, resultWaitCount)
					resultWaitCount = 0 // Reset counter
				}
			}
		case <-stopChan:
			return
		}
	}
}

// processBatch runs bip39 derivation for each password in the batch.
func processBatch(batch batchItem, mnemonic string, config *Config) workerResult {
	if len(batch.passwords) == 0 {
		return workerResult{
			batchNumber: batch.batchNumber,
			passwords:   []string{},
			foundPassword: nil,
			progress: batch.progress,
		}
	}
	var found *string

	for _, pw := range batch.passwords {
		var derivedAddresses []string
		var err error
		derivedAddresses, err = GetAddresses(
			config.FindAddressType,
			mnemonic,
			pw,
			config.AccountStart,
			config.AccountEnd,
			config.AddressStart,
			config.AddressEnd,
		)
		if err != nil {
			log.Fatalf("GetAddresses error: %v", err)
		}

		// Check all derived addresses
		for _, addr := range derivedAddresses {
			if strings.EqualFold(addr, config.FindAddress) {
				copyP := pw
				found = &copyP
				break
			}
		}
		if found != nil {
			break
		}
	}

	return workerResult{
		batchNumber: batch.batchNumber,
		passwords:   batch.passwords,
		foundPassword: found,
		progress: batch.progress,
	}
}
