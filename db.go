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

// Updated schema to rename "checked_password" to "password", adding generation_id (ON DELETE SET NULL)
// and a checked field (default 0), edited in place (no new migration for simplicity).
const createSchema = `
CREATE TABLE IF NOT EXISTS app_config (
	max_db_size_mb INTEGER NOT NULL DEFAULT 10240  -- Default to 10GB
);

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

CREATE TABLE IF NOT EXISTS password (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	config_id INTEGER NOT NULL,
	str TEXT NOT NULL,
	checked INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(config_id) REFERENCES config(id) ON DELETE CASCADE,
	UNIQUE(config_id, str)
);

CREATE INDEX IF NOT EXISTS idx_password_checked ON password(checked, id);
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

	if err := ensureAppConfigExists(db); err != nil {
		return nil, err
	}
	_, err = db.Exec(`PRAGMA optimize`)
	if err != nil {
		return nil, fmt.Errorf("failed to optimize: %w", err)
	}

	return db, nil
}

func ensureAppConfigExists(db *sql.DB) error {
	var existing int
	err := db.QueryRow("SELECT max_db_size_mb FROM app_config LIMIT 1").Scan(&existing)
	if err == sql.ErrNoRows {
		_, err := db.Exec("INSERT INTO app_config (max_db_size_mb) VALUES (10240)") // Default 10GB
		if err != nil {
			return fmt.Errorf("failed to insert default app_config row: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to read from app_config: %w", err)
	}
	return nil
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

// updateGenerationProgress updates generation.progress with the given string.
func updateGenerationProgress(db *sql.DB, generationID int, progress string, generatedCount int64, elapsedMs int64) error {
	_, err := db.Exec(`
		UPDATE generation
		SET progress = ?, generated_count = ?, elapsed_ms = ?
		WHERE id = ?
	`, progress, generatedCount, elapsedMs, generationID)
	return err
}

// insertPasswords inserts the given slice of passwords into the password table
// with checked=0, using a single multi-row INSERT statement.
func insertPasswords(db *sql.DB, configID int, passwords []string) error {
	if len(passwords) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin InsertPasswords tx: %w", err)
	}

	// Build the multi-row insert query.
	// For each password, we add a placeholder "(?, ?)" and append the configID and the password as arguments.
	placeholders := make([]string, len(passwords))
	args := make([]interface{}, 0, len(passwords)*2)
	for i, pw := range passwords {
		placeholders[i] = "(?, ?)"
		args = append(args, configID, pw)
	}
	query := fmt.Sprintf("INSERT OR IGNORE INTO password (config_id, str) VALUES %s", strings.Join(placeholders, ","))

	if _, err := tx.Exec(query, args...); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to execute multi-row insert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit InsertPasswords tx: %w", err)
	}

	return nil
}

// markPasswordsChecked sets the checked=1 for the given password IDs.
func markPasswordsChecked(db *sql.DB, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	// Build placeholder
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	qMarks := strings.Join(placeholders, ",")
	query := fmt.Sprintf(`
		UPDATE password
		SET checked = 1
		WHERE id IN (%s)
	`, qMarks)

	_, err := db.Exec(query, args...)

	// Prune if needed.
	if err := pruneIfOverLimit(db); err != nil {
		log.Printf("Warning: PruneIfOverLimit failed: %v", err)
	}
	return err
}

// pruneIfOverLimit checks if the db is over the configured max_db_size_mb in app_config,
// and if so, it deletes from password in ascending id order until under limit.
func pruneIfOverLimit(db *sql.DB) error {
	var maxMB int64
	err := db.QueryRow("SELECT max_db_size_mb FROM app_config LIMIT 1").Scan(&maxMB)
	if err != nil {
		return fmt.Errorf("failed to fetch max_db_size_mb: %w", err)
	}
	if maxMB <= 0 {
		return nil
	}

	pageCount := int64(0)
	pageSize := int64(0)
	if err := db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
		return fmt.Errorf("failed to read page_count: %w", err)
	}
	if err := db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return fmt.Errorf("failed to read page_size: %w", err)
	}
	currentSizeBytes := pageCount * pageSize
	maxBytes := maxMB * 1024 * 1024

	if currentSizeBytes <= maxBytes {
		return nil
	}

	log.Printf("DB size %d bytes exceeds max %d bytes. Pruning password...", currentSizeBytes, maxBytes)
	deleteBatchSize := 100000
	for i := 0; i < 1000000; i++ {
		oldSizeBytes := currentSizeBytes
		if err := pruneOnce(db, deleteBatchSize); err != nil {
			return fmt.Errorf("failed to prune rows: %w", err)
		}
		if err := db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
			return fmt.Errorf("failed to read page_count after prune: %w", err)
		}
		currentSizeBytes = pageCount * pageSize
		if currentSizeBytes == oldSizeBytes {
			log.Printf("Pruning did not reduce DB size; stopping further pruning.")
			break
		}
		if currentSizeBytes <= maxBytes {
			break
		}
	}
	_, err = db.Exec(`PRAGMA optimize`)
	if err != nil {
		return fmt.Errorf("failed to optimize: %w", err)
	}
	return nil
}

// pruneOnce deletes a batch of rows from the password table in ascending id order.
func pruneOnce(db *sql.DB, batch int) error {
	_, err := db.Exec(`
		DELETE FROM password
		WHERE id IN (
			SELECT id FROM password
			WHERE checked = 1
			ORDER BY id ASC
			LIMIT ?
		)
	`, batch)
	return err
}

// HashMnemonic lowercases + trims the mnemonic and returns its SHA-256 hex string.
func HashMnemonic(mnemonic string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(mnemonic))))
	return hex.EncodeToString(h[:])
}

// countUnchecked returns how many passwords for this generation have checked=0.
func countUnchecked(db *sql.DB) (int, error) {
	var cnt int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM password
		WHERE checked = 0
	`).Scan(&cnt)
	return cnt, err
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

// fetchUncheckedBatch grabs up to batchSize passwords (id, str) with checked=0,
// starting after the given cursor ID.
func fetchUncheckedBatch(db *sql.DB, batchSize int, cursorID int) ([]passwordRow, error) {
	// Select rows that are not checked and have id > cursorID
	rows, err := db.Query(`
		SELECT id, str
		FROM password
		WHERE checked = 0 AND id > ?
		ORDER BY id ASC
		LIMIT ?
	`, cursorID, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []passwordRow
	for rows.Next() {
		var r passwordRow
		if err := rows.Scan(&r.ID, &r.Str); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
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

// passwordRow represents a row from the password table that we need to process.
type passwordRow struct {
	ID  int
	Str string
}

// ClearPasswords truncates the password table, optimizes, and vacuums the database.
func ClearPasswords(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Truncate the password table.
	if _, err := tx.Exec("DELETE FROM password"); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to delete from password table: %w", err)
	}

	// Reset the autoincrement counter.
	if _, err := tx.Exec("DELETE FROM sqlite_sequence WHERE name='password'"); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to reset autoincrement: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Run optimize and vacuum outside the transaction
	if _, err := db.Exec("PRAGMA optimize"); err != nil {
		return fmt.Errorf("failed to optimize: %w", err)
	}
	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("failed to vacuum: %w", err)
	}

	return nil
}
