package bipbf

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	"github.com/tidwall/shardmap"
)

type RuntimeArgs struct {
	NumWorkers   int
	BatchSize    int
	MaxCacheLen  int  // Maximum number of passwords to keep in cache
	CacheEnabled bool // Whether to use the cache for deduplication
}

// RunStrategy is a generic generation strategy runner that spawns the aggregator, workers, reader, and the
// strategy's generator function.
func RunStrategy(
	db *sql.DB,
	config *Config,
	gen *Generation,
	mnemonic string,
	runtimeArgs RuntimeArgs,
	strategy Strategy,
	discordBot *DiscordBot,
	cache *shardmap.Map,
) (string, error) {
	if gen.Done == 1 {
		log.Printf("RunStrategy: Generation %d is already done. Skipping.\n", gen.ID)
		return "", nil
	}

	// Possibly the user found the password previously
	foundPwd, err := getConfigFoundPassword(db, config.ID)
	if err != nil {
		return "", fmt.Errorf("RunStrategy: failed to check found_password: %w", err)
	}
	if foundPwd != "" {
		log.Printf("RunStrategy: Password was already found previously: %s", foundPwd)
		return foundPwd, nil
	}

	var wg sync.WaitGroup
	var workerWg sync.WaitGroup

	foundCh := make(chan string, 1)                               // signals found password
	resultChan := make(chan workerResult, runtimeArgs.NumWorkers) // from workers
	batchChan := make(chan batchItem, runtimeArgs.NumWorkers)     // to workers

	stopChan := make(chan struct{})

	// aggregator
	wg.Add(1)
	go func() {
		defer wg.Done()
		aggregator(db, gen, resultChan, foundCh, stopChan, runtimeArgs, cache)
	}()

	// spawn workers
	for i := 0; i < runtimeArgs.NumWorkers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			worker(mnemonic, config, batchChan, resultChan, stopChan)
		}()
	}

	// goroutine to close resultChan when all workers finish
	go func() {
		workerWg.Wait()
		close(resultChan)
	}()

	// generator
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(batchChan)
		generator(db, config.ID, gen, runtimeArgs, strategy, batchChan, stopChan, discordBot, cache)
	}()

	// Now wait for either a found password or aggregator exit
	found := <-foundCh
	if found != "" {
		markConfigFoundPassword(db, config.ID, found)
		updateGenerationDone(db, gen.ID)
	}

	close(stopChan)

	// Drain channels to ensure no goroutine is blocked writing
	go func() {
		for range batchChan {
		}
	}()
	go func() {
		for range resultChan {
		}
	}()

	wg.Wait()
	return found, nil
}
