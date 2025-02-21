package bipbf

import (
	"database/sql"
	"log"
	"time"
)

// reader reads un-checked passwords from the DB in batches and sends them
// to workers. If there are no un-checked passwords available and the generation
// is not done, it waits and tries again.
func reader(
	db *sql.DB,
	batchSize int,
	batchChan chan<- batchItem,
	stopReader <-chan struct{},
) {
	defer close(batchChan)

	cursorID := 0 // Track the last ID we've seen

	for {
		select {
		case <-stopReader:
			return
		default:
		}

		// fetch up to batchSize un-checked rows after cursorID
		rows, err := fetchUncheckedBatch(db, batchSize, cursorID)
		if err != nil {
			log.Printf("runDbReader: fetchUncheckedBatch error: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		if len(rows) == 0 {
			// none found, but generation isn't done yet => wait
			time.Sleep(1 * time.Second)
			continue
		}

		// Update cursor to last ID in batch
		cursorID = rows[len(rows)-1].ID

		select {
		case <-stopReader:
			return
		case batchChan <- batchItem{rows: rows}:
		}
	}
}
