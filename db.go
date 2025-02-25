package bipbf

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const createSchema = `
CREATE TABLE IF NOT EXISTS config (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	mnemonic_hash TEXT NOT NULL,
	find_address TEXT NOT NULL,
	find_address_type TEXT NOT NULL,
	-- account/address index ranges
	account_start INTEGER NOT NULL DEFAULT 0,
	account_end INTEGER NOT NULL DEFAULT 0,
	address_start INTEGER NOT NULL DEFAULT 0,
	address_end INTEGER NOT NULL DEFAULT 0,
	found_password TEXT,
	UNIQUE(mnemonic_hash, find_address, account_start, account_end, address_start, address_end)
);

CREATE TABLE IF NOT EXISTS generation (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	generation_type INTEGER NOT NULL,
	done INTEGER NOT NULL DEFAULT 0,
	params TEXT NOT NULL,
	progress TEXT,
	-- generated_count is the number of passwords generated so far for this generation.
	generated_count INTEGER NOT NULL DEFAULT 0,
	-- total_count is the total number of passwords possible for this generation (set at creation).
	total_count INTEGER NOT NULL DEFAULT 0,
	elapsed_ms INTEGER NOT NULL DEFAULT 0,
	config_id INTEGER NOT NULL,
	UNIQUE(config_id, generation_type, params),
	FOREIGN KEY(config_id) REFERENCES config(id) ON DELETE CASCADE
);
`

var migrations = []string{
	createSchema,
}

// InitDB initializes the database with the required schema.
func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite db: %w", err)
	}

	pragmas := `
		PRAGMA journal_mode = wal;
		PRAGMA synchronous = normal;
		PRAGMA analysis_limit = 1000;
		PRAGMA busy_timeout = 5000;
	`
	if _, err := db.Exec(pragmas); err != nil {
		return nil, fmt.Errorf("failed to set pragmas: %w", err)
	}

	var userVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&userVersion); err != nil {
		return nil, fmt.Errorf("failed to retrieve user_version: %w", err)
	}

	// Run migrations if needed (in a real scenario you'd handle versioning properly).
	if userVersion < len(migrations) {
		tx, err := db.Begin()
		if err != nil {
			return nil, fmt.Errorf("failed to begin migration transaction: %w", err)
		}
		for v := userVersion + 1; v <= len(migrations); v++ {
			_, err := tx.Exec(migrations[v-1])
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("failed to migrate to version %d: %w", v, err)
			}
			_, err = tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v))
			if err != nil {
				tx.Rollback()
				return nil, fmt.Errorf("failed to set user_version to %d: %w", v, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("failed to commit migration transaction: %w", err)
		}
	}

	_, err = db.Exec(`PRAGMA optimize`)
	if err != nil {
		return nil, fmt.Errorf("failed to optimize: %w", err)
	}

	return db, nil
}

// Config represents a row in the config table
type Config struct {
	ID              int
	MnemonicHash    string
	FindAddress     string
	FindAddressType string
	AccountStart    int
	AccountEnd      int
	AddressStart    int
	AddressEnd      int
	FoundPassword   sql.NullString
}

// GetOrCreateConfig returns the Config for the given parameters.
// If not present, it creates one. The second return value indicates if a password was found.
func GetOrCreateConfig(db *sql.DB, mnemonicHash, address, addressType string, accountStart, accountEnd, addressStart, addressEnd int) (*Config, bool, error) {
	mnemonicHash = strings.ToLower(mnemonicHash)
	address = strings.ToLower(address)
	addressType = strings.ToLower(addressType)

	config := &Config{
		MnemonicHash:    mnemonicHash,
		FindAddress:     address,
		FindAddressType: addressType,
		AccountStart:    accountStart,
		AccountEnd:      accountEnd,
		AddressStart:    addressStart,
		AddressEnd:      addressEnd,
	}

	selectQuery := `
		SELECT id, found_password
		FROM config
		WHERE mnemonic_hash = ? AND find_address = ? AND account_start = ? AND account_end = ? AND address_start = ? AND address_end = ?
		LIMIT 1
	`
	err := db.QueryRow(selectQuery, mnemonicHash, address, accountStart, accountEnd, addressStart, addressEnd).Scan(&config.ID, &config.FoundPassword)
	if err == sql.ErrNoRows {
		// Insert
		res, err2 := db.Exec(`
			INSERT INTO config (mnemonic_hash, find_address, find_address_type, account_start, account_end, address_start, address_end)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, mnemonicHash, address, addressType, accountStart, accountEnd, addressStart, addressEnd)
		if err2 != nil {
			return nil, false, fmt.Errorf("failed to insert config: %w", err2)
		}
		newID, _ := res.LastInsertId()
		config.ID = int(newID)
		return config, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("failed to select config: %w", err)
	}

	return config, config.FoundPassword.Valid, nil
}

// markConfigFoundPassword updates config.found_password for the given configID.
func markConfigFoundPassword(db *sql.DB, configID int, foundPassword string) {
	_, err := db.Exec(`
		UPDATE config
		SET found_password = ?
		WHERE id = ?
	`, foundPassword, configID)
	if err != nil {
		log.Printf("Error updating config found_password: %v", err)
	}
}

// Generation is used to represent a row in the generation table.
type Generation struct {
	ID             int
	GenerationType int
	Done           int
	Params         string
	Progress       sql.NullString
	GeneratedCount int64
	TotalCount     int64
	ElapsedMs      int64
}

// GetOrCreateGeneration finds or creates a generation row for the given configID.
func GetOrCreateGeneration(db *sql.DB, configID int, generationType int, params string) (*Generation, error) {
	selectQuery := `
		SELECT id, generation_type, done, params, progress, generated_count, total_count, elapsed_ms
		FROM generation
		WHERE config_id = ? AND generation_type = ? AND params = ?
		LIMIT 1
	`
	var gen Generation
	err := db.QueryRow(selectQuery, configID, generationType, params).Scan(
		&gen.ID, &gen.GenerationType, &gen.Done, &gen.Params, &gen.Progress,
		&gen.GeneratedCount, &gen.TotalCount, &gen.ElapsedMs,
	)
	if err == sql.ErrNoRows {
		res, err2 := db.Exec(`
			INSERT INTO generation (generation_type, params, config_id)
			VALUES (?, ?, ?)
		`, generationType, params, configID)
		if err2 != nil {
			return nil, fmt.Errorf("failed to insert generation: %w", err2)
		}
		newID, _ := res.LastInsertId()
		gen.ID = int(newID)
		gen.Done = 0
		gen.Params = params
		gen.Progress = sql.NullString{String: "", Valid: false}
		gen.GeneratedCount = 0
		gen.TotalCount = 0
		gen.ElapsedMs = 0
		return &gen, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to select generation: %w", err)
	}
	return &gen, nil
}

// updateGenerationDone sets generation.done=1 for the specified generation.
func updateGenerationDone(db *sql.DB, generationID int) error {
	_, err := db.Exec(`
		UPDATE generation
		SET done = 1
		WHERE id = ?
	`, generationID)
	return err
}

// updateGenerationCountAndTime updates just the generated_count and elapsed_ms fields.
func updateGenerationCountAndTime(db *sql.DB, generationID int, generatedCount int64, elapsedMs int64) error {
	_, err := db.Exec(`
		UPDATE generation
		SET generated_count = ?, elapsed_ms = ?
		WHERE id = ?
	`, generatedCount, elapsedMs, generationID)
	return err
}

// updateGenerationProgress updates just the progress field.
func updateGenerationProgress(db *sql.DB, generationID int, progress string) error {
	_, err := db.Exec(`
		UPDATE generation
		SET progress = ?
		WHERE id = ?
	`, progress, generationID)
	return err
}

// HashMnemonic lowercases + trims the mnemonic and returns its SHA-256 hex string.
func HashMnemonic(mnemonic string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(mnemonic))))
	return hex.EncodeToString(h[:])
}

// getGenerationByID fetches a generation row by ID.
func getGenerationByID(db *sql.DB, generationID int) (*Generation, error) {
	row := db.QueryRow(`
		SELECT id, generation_type, done, params, progress, generated_count, total_count, elapsed_ms
		FROM generation
		WHERE id = ?
		LIMIT 1
	`, generationID)
	var g Generation
	err := row.Scan(&g.ID, &g.GenerationType, &g.Done, &g.Params, &g.Progress, &g.GeneratedCount, &g.TotalCount, &g.ElapsedMs)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// getConfigFoundPassword is a convenience function to fetch config.found_password.
func getConfigFoundPassword(db *sql.DB, configID int) (string, error) {
	var fp sql.NullString
	err := db.QueryRow(`SELECT found_password FROM config WHERE id = ?`, configID).Scan(&fp)
	if err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", err
	}
	if fp.Valid {
		return fp.String, nil
	}
	return "", nil
}

// DeleteGeneration deletes a generation record by ID.
func DeleteGeneration(db *sql.DB, generationID int) error {
	_, err := db.Exec(`DELETE FROM generation WHERE id = ?`, generationID)
	if err != nil {
		return fmt.Errorf("failed to delete generation: %w", err)
	}
	return nil
}
