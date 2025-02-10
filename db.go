package bipbf

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS naive_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    charset TEXT NOT NULL,
    length INTEGER NOT NULL,
    last_processed_pw TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    address TEXT NOT NULL,
    address_type TEXT NOT NULL,
    found_password TEXT,
    done INTEGER NOT NULL DEFAULT 0,
    UNIQUE(charset, length, mnemonic, address, address_type)
);
`

type NaiveRun struct {
	ID               int
	Charset          string
	Length           int
	LastProcessedStr string
	Mnemonic         string
	Address          string
	AddressType      string
	FoundPassword    *string
	Done             int
}

// GetExistingFoundPassword checks if there's already a found_password for (charset, mnemonic, address, addressType).
// If found, returns that string (and true). Otherwise returns ("", false).
func GetExistingFoundPassword(db *sql.DB, charset, mnemonic, address, addressType string) (string, bool, error) {
	query := `
		SELECT found_password
		FROM naive_run
		WHERE charset = ? AND mnemonic = ? AND address = ? AND address_type = ? AND found_password IS NOT NULL
		LIMIT 1
	`
	row := db.QueryRow(query, charset, mnemonic, address, addressType)
	var found *string
	err := row.Scan(&found)
	if err == sql.ErrNoRows {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	if found != nil {
		return *found, true, nil
	}
	return "", false, nil
}

// InitDB creates (if needed) and returns a reference to the SQLite DB.
func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite db: %w", err)
	}

	// Create table if not exists
	if _, err := db.Exec(createTableSQL); err != nil {
		return nil, fmt.Errorf("failed to create naive_run table: %w", err)
	}

	return db, nil
}

// GetOrCreateNaiveRun retrieves the row for (charset, length, mnemonic, address, addressType).
// If none exists, it creates one with last_processed_pw = "" and done = 0.
func GetOrCreateNaiveRun(db *sql.DB, charset string, length int, mnemonic, address, addressType string) (*NaiveRun, error) {
	// First attempt to SELECT
	selectQuery := `
		SELECT id, charset, length, last_processed_pw, mnemonic, address, address_type, found_password, done
		FROM naive_run
		WHERE charset = ? AND length = ? AND mnemonic = ? AND address = ? AND address_type = ?
		LIMIT 1
	`
	row := db.QueryRow(selectQuery, charset, length, mnemonic, address, addressType)
	var ps NaiveRun
	var tempFound sql.NullString
	err := row.Scan(&ps.ID, &ps.Charset, &ps.Length, &ps.LastProcessedStr, &ps.Mnemonic, &ps.Address, &ps.AddressType, &tempFound, &ps.Done)
	if err == sql.ErrNoRows {
		// Create the row
		insertQuery := `
			INSERT INTO naive_run (charset, length, last_processed_pw, mnemonic, address, address_type, found_password, done)
			VALUES (?, ?, ?, ?, ?, ?, NULL, 0)
		`
		res, insertErr := db.Exec(insertQuery, charset, length, "", mnemonic, address, addressType)
		if insertErr != nil {
			return nil, fmt.Errorf("failed to insert naive_run row: %w", insertErr)
		}
		newID, _ := res.LastInsertId()
		ps = NaiveRun{
			ID:               int(newID),
			Charset:          charset,
			Length:           length,
			LastProcessedStr: "",
			Mnemonic:         mnemonic,
			Address:          address,
			AddressType:      addressType,
			FoundPassword:    nil,
			Done:             0,
		}
		return &ps, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to select naive_run row: %w", err)
	}

	if tempFound.Valid {
		foundStr := tempFound.String
		ps.FoundPassword = &foundStr
	} else {
		ps.FoundPassword = nil
	}
	return &ps, nil
}
