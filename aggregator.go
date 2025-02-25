package bipbf

import (
	"database/sql"
	"log"

	"github.com/tidwall/shardmap"
)

// aggregator collects results from the workers, marks rows as checked=1, and
// signals if a password is found.
func aggregator(
	db *sql.DB,
	gen *Generation,
	resultChan <-chan workerResult,
	foundCh chan<- string,
	stopChan <-chan struct{},
	runtimeArgs RuntimeArgs,
	cache *shardmap.Map,
) {
	defer close(foundCh)
	found := false

	// Track the next expected batch number
	nextExpectedBatch := 0

	// Store out-of-order batches
	pendingBatches := make(map[int]workerResult)

	for {
		select {
		case <-stopChan:
			// aggregator asked to stop, if not found then send empty
			if !found {
				foundCh <- ""
			}
			return

		case res, ok := <-resultChan:
			if !ok {
				// channel closed, no more results
				if !found {
					foundCh <- ""
				}
				return
			}

			// Add proccessed passwords to cache
			// Check if cache size exceeds the maximum allowed length
			if runtimeArgs.CacheEnabled && cache != nil {
				cacheLen := cache.Len()
				if runtimeArgs.MaxCacheLen > 0 && cacheLen > runtimeArgs.MaxCacheLen {
					// Track how many items we need to remove
					toRemove := cacheLen - runtimeArgs.MaxCacheLen + len(res.passwords)
					// Collect keys to delete
					keysToDelete := make([]string, 0, toRemove)

					// Use Range to collect keys to delete
					cache.Range(func(key string, value interface{}) bool {
						keysToDelete = append(keysToDelete, key)
						return len(keysToDelete) < toRemove // continue until we've collected enough
					})

					// Delete the collected keys
					for _, key := range keysToDelete {
						cache.Delete(key)
					}
				}

				// Now add the new passwords to cache
				for _, pw := range res.passwords {
					cache.Set(pw, true)
				}
			}

			// Store the result
			pendingBatches[res.batchNumber] = res

			// Process batches in order
			for {
				nextBatch, exists := pendingBatches[nextExpectedBatch]
				if !exists {
					break // Wait for the next expected batch
				}

				// We have the next batch in sequence, process it
				delete(pendingBatches, nextExpectedBatch)
				nextExpectedBatch++

				// Update generation progress in the database
				if nextBatch.progress != "" {
					// Progress is already a JSON string, no need to marshal
					err := updateGenerationProgress(db, gen.ID, nextBatch.progress)
					if err != nil {
						log.Printf("Error updating generation progress: %v", err)
					}
				}
			}

			// Check if found
			if !found && res.foundPassword != nil {
				found = true
				foundCh <- *res.foundPassword
				return
			}
		}
	}
}
