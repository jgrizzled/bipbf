package bipbf

import (
	"bipbf/strats/exhaustive"
	"bipbf/strats/variation"
	"bipbf/strats/wordlist"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestExhaustiveBruteForce tests the exhaustive approach
func TestExhaustiveBruteForce(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "exhaustive-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize DB: %v", err)
	}
	defer db.Close()
	defer os.RemoveAll(tmpDir)

	// Setup a test mnemonic + address
	// We do NOT store mnemonic in DB, only mnemonic_hash.
	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	hashHex := HashMnemonic(mnemonic)

	// For a quick test, let's do a 1-char password that results in a known BTC segwit address
	// We'll just re-use the existing code logic from the old test: password "a" => address ...
	address := "bc1q0dc8v2u2m8twr8kt5x4l8544g9dnc2z79fwvw2"
	addressType := "btc-bech32"
	password := "a"

	// Create config
	cfg, foundAlready, err := GetOrCreateConfig(db, hashHex, address, addressType, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetOrCreateConfig error: %v", err)
	}
	if foundAlready {
		t.Fatalf("Expected config not to have found_password yet, but found %s", cfg.FoundPassword.String)
	}

	// Create generation for exhaustive
	params := map[string]interface{}{
		"charset": "ab", // minimal
		"length":  float64(1),
	}
	paramsBytes, _ := json.Marshal(params)
	gen, err := GetOrCreateGeneration(db, cfg.ID, 1, string(paramsBytes))
	if err != nil {
		t.Fatalf("GetOrCreateGeneration error: %v", err)
	}

	if gen.Done == 1 {
		t.Fatalf("Expected generation not done yet.")
	}

	// Now run the exhaustive brute force
	runtimeArgs := RuntimeArgs{
		NumWorkers: 2,
		BatchSize:  10,
	}

	strategy, err := exhaustive.NewStrategy(params)
	if err != nil {
		t.Fatalf("Error creating exhaustive strategy: %v", err)
		return
	}

	foundPwd, err := RunStrategy(
		db,
		cfg,
		gen,
		mnemonic,
		runtimeArgs,
		strategy,
		nil,
	)
	if err != nil {
		t.Fatalf("ExhaustiveBruteForce error: %v", err)
	}

	if foundPwd != password {
		t.Fatalf("expected found password = %q, got %q", password, foundPwd)
	}

	// Check that we found the password in DB too
	dbFoundPwd, err := getConfigFoundPassword(db, cfg.ID)
	if err != nil {
		t.Fatalf("failed to check found_password after run: %v", err)
	}
	if dbFoundPwd != password {
		t.Fatalf("expected found db password = %q, got %q", password, dbFoundPwd)
	}

	// Check generation is done
	gen2, err := getGenerationByID(db, gen.ID)
	if err != nil {
		t.Fatalf("getGen error: %v", err)
	}
	if gen2.Done != 1 {
		t.Fatalf("Expected generation done=1, got %d", gen2.Done)
	}
}

func BenchmarkVariationStrategy(b *testing.B) {
	runtimeArgs := RuntimeArgs{
		NumWorkers: runtime.NumCPU() - 1,
		BatchSize:  10000,
	}
	tmpDir, err := os.MkdirTemp("", "variation-benchmark-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		b.Fatalf("Failed to initialize DB: %v", err)
	}
	defer db.Close()
	defer os.RemoveAll(tmpDir)

	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	hashHex := HashMnemonic(mnemonic)

	address := "bc1qxx59hankh48trp5ntvk0twzc5dkcqslrckznd4"
	addressType := "btc-bech32"
	password := "aaz"

	cfg, foundAlready, err := GetOrCreateConfig(db, hashHex, address, addressType, 0, 0, 0, 0)
	if err != nil {
		b.Fatalf("GetOrCreateConfig error: %v", err)
	}
	if foundAlready {
		b.Fatalf("Expected config not to have found_password yet, but found %s", cfg.FoundPassword.String)
	}
	params := map[string]interface{}{
		"base_password": "abc",
		"charset":       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?`~ ",
		"operations":    float64(2),
	}
	paramsBytes, _ := json.Marshal(params)
	gen, err := GetOrCreateGeneration(db, cfg.ID, 1, string(paramsBytes))
	if err != nil {
		b.Fatalf("GetOrCreateGeneration error: %v", err)
	}

	strategy, err := variation.NewStrategy(params)
	if err != nil {
		b.Fatalf("Error creating exhaustive strategy: %v", err)
		return
	}
	foundPwd, err := RunStrategy(
		db,
		cfg,
		gen,
		mnemonic,
		runtimeArgs,
		strategy,
		nil,
	)
	if err != nil {
		b.Fatalf("Error: %v", err)
	}

	if foundPwd != password {
		b.Fatalf("expected found password = %q, got %q", password, foundPwd)
	}
}

func BenchmarkWordlistStrategy(b *testing.B) {
	runtimeArgs := RuntimeArgs{
		NumWorkers: runtime.NumCPU() - 1,
		BatchSize:  10000,
	}
	tmpDir, err := os.MkdirTemp("", "variation-benchmark-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := InitDB(dbPath)
	if err != nil {
		b.Fatalf("Failed to initialize DB: %v", err)
	}
	defer db.Close()
	defer os.RemoveAll(tmpDir)

	mnemonic := "swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
	hashHex := HashMnemonic(mnemonic)

	address := "bc1q8g84p6xwrhl8qeymmfd2d9c2ql4vdwxrspwmp6"
	addressType := "btc-bech32"
	password := "ten-nine-eight-seven-six"

	cfg, foundAlready, err := GetOrCreateConfig(db, hashHex, address, addressType, 0, 0, 0, 0)
	if err != nil {
		b.Fatalf("GetOrCreateConfig error: %v", err)
	}
	if foundAlready {
		b.Fatalf("Expected config not to have found_password yet, but found %s", cfg.FoundPassword.String)
	}
	params := map[string]interface{}{
		"wordlist":  []interface{}{"one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"},
		"length":    float64(5),
		"separator": "-",
	}
	paramsBytes, _ := json.Marshal(params)
	gen, err := GetOrCreateGeneration(db, cfg.ID, 1, string(paramsBytes))
	if err != nil {
		b.Fatalf("GetOrCreateGeneration error: %v", err)
	}

	strategy, err := wordlist.NewStrategy(params)
	if err != nil {
		b.Fatalf("Error creating strategy: %v", err)
		return
	}
	foundPwd, err := RunStrategy(
		db,
		cfg,
		gen,
		mnemonic,
		runtimeArgs,
		strategy,
		nil,
	)
	if err != nil {
		b.Fatalf("Error: %v", err)
	}

	if foundPwd != password {
		b.Fatalf("expected found password = %q, got %q", password, foundPwd)
	}
}
