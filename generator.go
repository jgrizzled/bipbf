package bipbf

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"
)

type Strategy struct {
	CalcTotalPossibilities func(params map[string]interface{}) (int64, error)
	GenerateNextNStrings   func(params map[string]interface{}, progress map[string]interface{}, n int) ([]string, map[string]interface{}, error)
}

// generator calls the generator function for a strategy.
// It reads the generation row (including params and progress), enumerates passwords,
// and inserts them into the password table in batches.
// stopChan is signaled when the aggregator finishes or the password is found.
func generator(
	db *sql.DB,
	configID int,
	genRow *Generation,
	runtimeArgs RuntimeArgs,
	strategy Strategy,
	stopChan <-chan struct{},
) {

	if genRow.Done == 1 {
		log.Printf("RunGenerator: generation %d is already done.", genRow.ID)
		return
	}

	var params map[string]interface{}
	if err := json.Unmarshal([]byte(genRow.Params), &params); err != nil {
		log.Printf("RunGenerator: error parsing exhaustive params: %v", err)
		return
	}

	// If total_count is 0, calculate and store it
	if genRow.TotalCount == 0 {
		tp, err := strategy.CalcTotalPossibilities(params)
		if err != nil {
			log.Fatalf("RunGenerator: error calculating total count: %v", err)
			return
		}

		_, err = db.Exec(`
			UPDATE generation
			SET total_count = ?
			WHERE id = ?`,
			tp, genRow.ID)
		if err != nil {
			log.Printf("RunGenerator: error storing total_count: %v", err)
			return
		}
		genRow.TotalCount = int64(tp)
	}

	// Initialize progress tracking
	var progress map[string]interface{}
	if genRow.Progress.Valid {
		if err := json.Unmarshal([]byte(genRow.Progress.String), &progress); err != nil {
			log.Printf("RunGenerator: error parsing progress JSON: %v", err)
			return
		}
	} else {
		progress = make(map[string]interface{})
	}

	lastPrintTime := time.Now()
	startTime := lastPrintTime
	var generatedThisRun int64 = 0
	iterationStart := time.Now()

	if _, ok := progress["last_password"]; !ok {
		log.Printf("Starting generation for length %v", params["length"])
	} else {
		overallProgress := (float64(genRow.GeneratedCount) / float64(genRow.TotalCount)) * 100.0
		log.Printf("Resuming generation, progress: %.2f%% complete", overallProgress)
	}

	for {
		// Allow the stop channel to trigger immediate exit
		select {
		case <-stopChan:
			return
		default:
		}

		// ------------------ Periodically print statistics ------------------
		if time.Since(lastPrintTime) >= 30*time.Second {
			now := time.Now()
			elapsedThisRun := now.Sub(startTime).Seconds()
			pps := float64(generatedThisRun) / elapsedThisRun
			overallProgress := (float64(genRow.GeneratedCount) / float64(genRow.TotalCount)) * 100.0
			remaining := genRow.TotalCount - genRow.GeneratedCount
			var etaSec float64
			if pps > 0 {
				etaSec = float64(remaining) / pps
			}
			log.Printf("Progress: %.2f%%, pps: %.2f, ETA: %v, Run Time: %v, Total Run Time: %v",
				overallProgress, pps, time.Duration(etaSec*float64(time.Second)), time.Duration(elapsedThisRun*float64(time.Second)), time.Duration(genRow.ElapsedMs*int64(time.Millisecond)))
			lastPrintTime = now
		}
		// -------------------------------------------------------------------------------------

		// Check unchecked passwords count
		uncheckedCount, err := countUnchecked(db)
		if err != nil {
			log.Printf("RunGenerator: error counting unchecked: %v", err)
			return
		}
		maxPending := runtimeArgs.BatchSize * runtimeArgs.NumWorkers * 2
		if uncheckedCount >= maxPending {
			time.Sleep(1 * time.Second)
			continue
		}

		// Generate the next batch of password strings
		strs, newProgress, err := strategy.GenerateNextNStrings(params, progress, runtimeArgs.BatchSize)
		if err != nil {
			log.Fatalf("RunGenerator: error generating next strings: %v", err)
			return
		}
		n := int64(len(strs))

		if n == 0 {
			// No more strings can be generated at this length
			break
		}

		// Insert the batch into the DB (ignoring duplicates).
		err = insertPasswords(db, configID, strs)
		if err != nil {
			log.Printf("RunGenerator: error inserting passwords: %v", err)
			return
		}

		progressJSON, err := json.Marshal(newProgress)
		if err != nil {
			log.Printf("RunGenerator: error marshaling progress: %v", err)
			return
		}

		iterationElapsed := time.Since(iterationStart).Milliseconds()
		genRow.ElapsedMs += iterationElapsed
		iterationStart = time.Now() // Reset the iteration timer

		genRow.GeneratedCount += n

		err = updateGenerationProgress(db, genRow.ID, string(progressJSON), genRow.GeneratedCount, genRow.ElapsedMs)
		if err != nil {
			log.Printf("RunGenerator: error updating generation progress: %v", err)
			return
		}

		generatedThisRun += n
		progress = newProgress // Update progress for the next iteration
	}

	log.Printf("Generation complete: total generated: %d passwords. Time elapsed: %v", genRow.GeneratedCount, time.Since(startTime))
	// Mark generation done
	updateGenerationDone(db, genRow.ID)
}
