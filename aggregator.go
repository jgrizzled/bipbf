package bipbf

import (
	"database/sql"
	"log"
)

// aggregator collects results from the workers, marks rows as checked=1, and
// signals if a password is found.
func aggregator(
	db *sql.DB,
	resultChan <-chan workerResult,
	foundCh chan<- string,
	stopChan <-chan struct{},
) {
	defer close(foundCh)
	found := false

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

			// Mark these row IDs as checked=1
			if len(res.rowIDs) > 0 {
				err := markPasswordsChecked(db, res.rowIDs)
				if err != nil {
					log.Printf("runAggregator: Error marking passwords checked: %v", err)
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
