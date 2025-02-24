package bipbf

import (
	"database/sql"
	"log"
)

// WriteOp represents a database write operation
type WriteOp interface {
	Execute(db *sql.DB) error
}

// InsertPasswordsOp represents a batch password insert operation
type InsertPasswordsOp struct {
	ConfigID int
	Strings  []string
}

func (op InsertPasswordsOp) Execute(db *sql.DB) error {
	return insertPasswords(db, op.ConfigID, op.Strings)
}

// MarkCheckedOp represents an operation to mark passwords as checked
type MarkCheckedOp struct {
	RowIDs []int
}

func (op MarkCheckedOp) Execute(db *sql.DB) error {
	return markPasswordsChecked(db, op.RowIDs)
}

// UpdateGenerationOp represents an operation to update generation progress
type UpdateGenerationOp struct {
	GenID          int
	Progress       string
	GeneratedCount int64
	ElapsedMs      int64
}

func (op UpdateGenerationOp) Execute(db *sql.DB) error {
	return updateGenerationProgress(db, op.GenID, op.Progress, op.GeneratedCount, op.ElapsedMs)
}

// writer is the central goroutine that handles all database write operations
func writer(db *sql.DB, writeChan <-chan WriteOp, stopChan <-chan struct{}) {
	for {
		select {
		case <-stopChan:
			return

		case op, ok := <-writeChan:
			if !ok {
				return
			}
			if err := op.Execute(db); err != nil {
				log.Fatalf("writer: error executing operation: %v", err)
			}
		}
	}
}
