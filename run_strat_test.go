package bipbf

import (
	"bipbf/strats/exhaustive"
	"encoding/json"
	"os"
	"path/filepath"
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
	cfgID, existingPwd, foundAlready, err := GetOrCreateConfig(db, hashHex, address, addressType)
	if err != nil {
		t.Fatalf("GetOrCreateConfig error: %v", err)
	}
	if foundAlready {
		t.Fatalf("Expected config not to have found_password yet, but found %s", existingPwd)
	}

	// Create generation for exhaustive
	params := map[string]interface{}{
		"charset": "ab", // minimal
		"length":  float64(1),
	}
	paramsBytes, _ := json.Marshal(params)
	gen, err := GetOrCreateGeneration(db, cfgID, 1, string(paramsBytes))
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

	strategy := Strategy{
		CalcTotalPossibilities: exhaustive.CalcTotalPossibilities,
		GenerateNextNStrings:   exhaustive.GenerateNextStrings,
	}

	foundPwd, err := RunStrategy(
		db,
		cfgID,
		gen,
		mnemonic,
		address,
		addressType,
		runtimeArgs,
		strategy,
	)
	if err != nil {
		t.Fatalf("ExhaustiveBruteForce error: %v", err)
	}

	if foundPwd != password {
		t.Fatalf("expected found password = %q, got %q", password, foundPwd)
	}

	// Check that we found the password in DB too
	dbFoundPwd, err := getConfigFoundPassword(db, cfgID)
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
