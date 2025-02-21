package bipbf

import (
	"log"
	"strings"
	"time"
)

// worker processes each batch by deriving addresses and checking if any match.
func worker(
	mnemonic string,
	address string,
	addressType string,
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

		res := processBatch(batch.rows, mnemonic, address, addressType)

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
func processBatch(rows []passwordRow, mnemonic, address, addressType string) workerResult {
	if len(rows) == 0 {
		return workerResult{
			rowIDs:        nil,
			foundPassword: nil,
		}
	}
	var found *string

	for _, row := range rows {
		pw := row.Str
		var derivedAddresses []string
		var err error
		derivedAddresses, err = GetAddresses(addressType, mnemonic, pw, 0, 0, 0, 0)
		if err != nil {
			log.Fatalf("GetAddresses error: %v", err)
		}
		if len(derivedAddresses) > 0 && strings.EqualFold(derivedAddresses[0], address) {
			copyP := pw
			found = &copyP
			break
		}
	}

	rowIDs := make([]int, len(rows))
	for i, r := range rows {
		rowIDs[i] = r.ID
	}

	return workerResult{
		rowIDs:        rowIDs,
		foundPassword: found,
	}
}
