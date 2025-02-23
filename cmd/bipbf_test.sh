#!/usr/bin/env bash

# Store original directory and build
ORIGINAL_DIR=$(pwd)
make build
BIPBF_BIN="${ORIGINAL_DIR}/bin/bipbf"

# Create and move to temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR" || exit 1

# Set up common environment variables
export BIPBF_MNEMONIC="swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
export BIPBF_ADDRESS_TYPE=btc-bech32
export BIPBF_ACCOUNT_END=1
export BIPBF_ADDRESS_END=1

# Helper function to run a test case
run_test() {
    local test_name=$1
    local expected=$2
    local cmd=$3

    rm -rf *db.sqlite*
    result=$("$BIPBF_BIN" $cmd 2>&1 | tee /dev/tty | grep -i "Found password:")
    if [[ $result != *"$expected"* ]]; then
        echo "$test_name failed: want '$expected', got '$result'"
        cleanup_and_exit 1
    fi
}

# Helper function to cleanup and exit
cleanup_and_exit() {
    local exit_code=$1
    rm -rf "$TEMP_DIR"
    exit "$exit_code"
}

# Test cases
# Exhaustive test
export BIPBF_ADDRESS="bc1qcqucsq05l7yxeclrkz68d30d8xl6xr7swup9kl"
run_test "Exhaustive" "aa" "--mode exhaustive --min-len 1 --max-len 2"

# Pwlist test
printf "bb\naa" > passwords.txt
run_test "Pwlist" "aa" "--mode pwlist"

# Variation test
run_test "Variation" "aa" "--mode variation --base ab --ops 1"

# Wordlist test
export BIPBF_ADDRESS="bc1qh4yk4rzj40mqztff4uh7pf58pahd968t087sgl"
printf "b\na" > wordlist.txt
run_test "Wordlist" "ab" "--mode wordlist --len 2"

echo "All tests passed"
cleanup_and_exit 0


