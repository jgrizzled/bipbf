#!/usr/bin/env bash

# Store original directory and build
ORIGINAL_DIR=$(pwd)
make build
BIPBF_BIN="${ORIGINAL_DIR}/bin/bipbf"

# Create and move to temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR" || exit 1

# Set up environment variables
export BIPBF_MNEMONIC="swarm security emotion rent eagle meadow submit panic myself list occur siege popular famous hint soon jealous hidden safe primary build quiz sea define"
export BIPBF_ADDRESS_TYPE=btc-bech32

# exhaustive test
export BIPBF_ADDRESS="bc1qcqucsq05l7yxeclrkz68d30d8xl6xr7swup9kl"
export BIPBF_ACCOUNT_END=1
export BIPBF_ADDRESS_END=1
result=$("$BIPBF_BIN" --mode exhaustive --min-len 1 --max-len 2 | grep -i "found")
if [[ $result != *"aa"* ]]; then
    echo "Exhaustive test failed: want 'aa', got '$result'"
    rm -rf "$TEMP_DIR"
    exit 1
fi
rm -rf *db.sqlite*

# pwlist test
printf "bb\naa" > passwords.txt
result=$("$BIPBF_BIN" --mode pwlist | grep -i "found")
if [[ $result != *"aa"* ]]; then
    echo "Pwlist test failed: want 'aa', got '$result'"
    rm -rf "$TEMP_DIR"
    exit 1
fi
rm -rf *db.sqlite*

# variation test
result=$("$BIPBF_BIN" --mode variation --base "ab" --ops 1 | grep -i "found")
if [[ $result != *"aa"* ]]; then
    echo "Variation test failed: want 'aa', got '$result'"
    rm -rf "$TEMP_DIR"
    exit 1
fi
rm -rf *db.sqlite*

# wordlist test
export BIPBF_ADDRESS="bc1qh4yk4rzj40mqztff4uh7pf58pahd968t087sgl"
export BIPBF_ACCOUNT_END=0
export BIPBF_ADDRESS_END=0
printf "b\na" > wordlist.txt
result=$("$BIPBF_BIN" --mode wordlist --len 2 | grep -i "found")
if [[ $result != *"ab"* ]]; then
    echo "Wordlist test failed: want 'ab', got '$result'"
    rm -rf "$TEMP_DIR"
    exit 1
fi
rm -rf *db.sqlite*

echo "All tests passed"
rm -rf "$TEMP_DIR"


