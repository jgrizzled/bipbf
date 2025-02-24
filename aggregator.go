package bipbf

// aggregator collects results from the workers, marks rows as checked=1, and
// signals if a password is found.
func aggregator(
	resultChan <-chan workerResult,
	foundCh chan<- string,
	writeChan chan<- WriteOp,
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

			if len(res.rowIDs) > 0 {
				writeOp := MarkCheckedOp{
					RowIDs: res.rowIDs,
				}
				writeChan <- writeOp
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
