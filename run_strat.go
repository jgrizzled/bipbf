package bipbf

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

type RuntimeArgs struct {
	NumWorkers int
	BatchSize  int
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
	stopReader := make(chan struct{})

	// aggregator
	wg.Add(1)
	go func() {
		defer wg.Done()
		aggregator(db, resultChan, foundCh, stopChan)
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

	// reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader(db, runtimeArgs.BatchSize, batchChan, stopReader)
	}()

	// generator
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stopReader) // Signal stopReader when generator finishes
		generator(db, config.ID, gen, runtimeArgs, strategy, stopChan, discordBot)
		time.Sleep(2 * time.Second) // Give reader a chance to read last batch
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

// workerResult is passed back from the workers to the aggregator.
type workerResult struct {
	rowIDs        []int
	foundPassword *string
}

// batchItem is passed to workers: a group of passwordRows to check.
type batchItem struct {
	rows []passwordRow
}
