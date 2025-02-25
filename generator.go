package bipbf

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/tidwall/shardmap"
)

type Strategy interface {
	GetTotalStrings() (int64, error)
	GenerateNextStrings(progress map[string]interface{}, n int) ([]string, map[string]interface{}, error)
}

// generator calls the generator function for a strategy.
// stopChan is signaled when the password is found.
func generator(
	db *sql.DB,
	configID int,
	genRow *Generation,
	runtimeArgs RuntimeArgs,
	strategy Strategy,
	batchChan chan<- batchItem,
	stopChan <-chan struct{},
	bot *DiscordBot,
	cache *shardmap.Map,
) {

	if genRow.Done == 1 {
		log.Printf("RunGenerator: generation %d is already done.", genRow.ID)
		return
	}

	batchNumber := 0

	// If total_count is 0, calculate and store it
	if genRow.TotalCount == 0 {
		tp, err := strategy.GetTotalStrings()
		if err != nil {
			log.Printf("RunGenerator: error calculating total count: %v", err)
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
	lastDiscordTime := lastPrintTime
	startTime := lastPrintTime
	var generatedThisRun int64 = 0

	// For sliding window pps calculation
	const slidingWindowDuration = 5 * time.Minute
	slidingWindowStart := time.Now()
	var slidingWindowCount int64 = 0

	// Store the initial elapsed time from previous runs
	initialElapsedMs := genRow.ElapsedMs

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

			// Calculate sliding window pps
			slidingWindowElapsed := now.Sub(slidingWindowStart).Seconds()
			var pps float64

			// If sliding window is full, calculate based on window
			if slidingWindowElapsed >= slidingWindowDuration.Seconds() {
				pps = float64(slidingWindowCount) / slidingWindowDuration.Seconds()
				// Reset sliding window
				slidingWindowStart = now
				slidingWindowCount = 0
			} else if slidingWindowElapsed > 0 {
				// Window not full yet, but we have some data
				pps = float64(slidingWindowCount) / slidingWindowElapsed
			} else {
				// Fallback to overall calculation if window just started
				pps = float64(generatedThisRun) / elapsedThisRun
			}

			overallProgress := (float64(genRow.GeneratedCount) / float64(genRow.TotalCount)) * 100.0
			remaining := genRow.TotalCount - genRow.GeneratedCount
			var etaSec float64
			if pps > 0 {
				etaSec = float64(remaining) / pps
			}

			// Calculate total elapsed time (previous runs + current run)
			totalElapsedMs := initialElapsedMs + int64(elapsedThisRun*1000)

			// Format durations without decimal places
			etaDuration := time.Duration(etaSec * float64(time.Second))
			runTimeDuration := time.Duration(elapsedThisRun * float64(time.Second))
			totalRunTimeDuration := time.Duration(totalElapsedMs * int64(time.Millisecond))

			logMessage := fmt.Sprintf("Progress: %.2f%%, PPS: %.2f, ETA: %s, Curr: %s, Total: %s",
				overallProgress, pps,
				formatDuration(etaDuration),
				formatDuration(runTimeDuration),
				formatDuration(totalRunTimeDuration))
			log.Print(logMessage)
			lastPrintTime = now

			if bot != nil && time.Since(lastDiscordTime) >= 24*time.Hour {
				if err := bot.SendMessage(logMessage); err != nil {
					log.Printf("Error sending Discord message: %v", err)
				}
				lastDiscordTime = now // Update lastDiscordTime
			}
		}
		// -------------------------------------------------------------------------------------

		// Generate the next batch of password strings
		strs, newProgress, err := strategy.GenerateNextStrings(progress, runtimeArgs.BatchSize)
		if err != nil {
			log.Printf("RunGenerator: error generating next strings: %v", err)
			return
		}
		n := int64(len(strs))

		if n == 0 {
			// No more strings can be generated
			break
		}

		// Marshal the progress to JSON string
		progressJSON, err := json.Marshal(newProgress)
		if err != nil {
			log.Printf("Error marshaling progress to JSON: %v", err)
			return
		}
		progressStr := string(progressJSON)

		// Deduplicate strings and filter out already processed passwords
		uniqueStrs := make([]string, 0, len(strs))
		seen := make(map[string]bool)

		for _, str := range strs {
			// Skip empty strings and duplicates
			if str != "" && !seen[str] {
				// Only check cache if cache is enabled
				if runtimeArgs.CacheEnabled && cache != nil {
					_, exists := cache.Get(str)
					if !exists {
						seen[str] = true
						uniqueStrs = append(uniqueStrs, str)
					}
				} else {
					// If cache is disabled, just check for duplicates in current batch
					seen[str] = true
					uniqueStrs = append(uniqueStrs, str)
				}
			}
		}

		// Update generated count and elapsed time
		genRow.GeneratedCount += n
		generatedThisRun += n
		slidingWindowCount += n // Update sliding window counter

		// Calculate elapsed time - only for database updates
		now := time.Now()
		genRow.ElapsedMs = initialElapsedMs + int64(now.Sub(startTime).Milliseconds())

		// Update the database with new count and time
		if err := updateGenerationCountAndTime(db, genRow.ID, genRow.GeneratedCount, genRow.ElapsedMs); err != nil {
			log.Printf("Error updating generation count and time: %v", err)
		}

		// Only send batch if there are passwords to process after filtering
		if len(uniqueStrs) > 0 {
			batchChan <- batchItem{batchNumber: batchNumber, passwords: uniqueStrs, progress: progressStr}
			batchNumber++
		}
		progress = newProgress
	}

	log.Printf("Generation complete.")
	// Mark generation done
	updateGenerationDone(db, genRow.ID)
}

// formatDuration formats a duration without decimal places for seconds
func formatDuration(d time.Duration) string {
	// Extract days, hours, minutes, seconds
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	// Format based on components present
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm%ds", days, h, m, s)
	} else if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	} else {
		return fmt.Sprintf("%ds", s)
	}
}
