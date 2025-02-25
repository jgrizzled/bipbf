# bipbf

**bipbf** is a brute force password-guessing tool for recovering BIP39 (mnemonic phrase) wallets (like created by Trezor or Ledger hardware wallets) where you have the seed phrase and a known address but lost the password (aka 25th word). It supports multiple modes of brute force, including exhaustive, password list, variation, and wordlist modes. Brute force runs can be interrupted and resumed.

BIP39 wallets are designed to be slow to brute force (performing 2048 rounds of SHA512 hashing on the mnemonic + password to derive the master private key). Thus, performing an exhaustive brute force (IE trying all possible combinations of characters from a charset) is not recommended. For password lengths > 7 characters, an exhaustive search is likely to take months, if not years, to complete.

Alternative, more intelligent brute force modes that are based on your known commonly used passwords are more likely to complete in a reasonable amount of time. The wordlist mode can try combinations of words or segments from your commonly used passwords, and the variation mode can try variations of your commonly used passwords.

This software is provided as-is, without any warranty or support. Users must ensure they are authorized to access the wallets they are attempting to recover.

## Requirements

- [Go](https://golang.org/dl/) (version 1.23+)

## Installation

1. **Clone the Repository:**

```bash
git clone https://github.com/jgrizzled/bipbf.git
cd bipbf
```

2. **Build the Application:**

Use the provided Makefile to build the binary:

```bash
make build
```

The executable will be in the `bin` directory.

## Configuration

You can configure bipbf using environment variables, a .env file, or command line flags. Configuration options in order of precedence:

1. Command line flags
2. Environment variables
3. .env file

You must specify the following:

- mnemonic: the BIP39 seed phrase
- address: the address to find
- address-type: the address type

### Supported Address Types

`btc-bech32` : Bech32 addresses with BIP84 derivation path (m/84'/0'/account'/0/index), ex "bc1..."

`btc-segwit` : Segwit addresses with BIP49 derivation path (m/49'/0'/account'/0/index), ex "3..."

`btc-legacy` : Legacy addresses with BIP44 derivation path (m/44'/0'/account'/0/index), ex "1..."

`eth` : Ethereum addresses with BIP44 derivation path (m/44'/60'/account'/0/index), ex "0x..."

You must know the account and address indices to use, or specify a range to search. Bitcoin wallets typically create a new address each time you receive a payment. Ethereum wallets typically use the same address for all transactions. Some wallet software lets you create multiple accounts for the same seed, incrementing the account index (however some Ethereum wallets actually increment the address index).

If not specified, the account and address indices default to 0. You can specify a range of accounts and addresses to search. For example, to check the first 2 accounts and the first 10 addresses of each account, set `--account-start 0` and `--account-end 1` and `--address-start 0` and `--address-end 9`. Note, searching for multiple addresses will slow down the brute force significantly.

### Wallet Configuration

#### CLI flags:

```
--mnemonic "your mnemonic phrase"
--address your_address
--address-type btc-bech32
--account-start 0 # Optional
--account-end 0 # Optional
--address-start 0 # Optional
--address-end 0 # Optional
```

#### Environment variables:

```bash
export BIPBF_MNEMONIC="your mnemonic phrase"
export BIPBF_ADDRESS=your_address
export BIPBF_ADDRESS_TYPE=btc-bech32
export BIPBF_ACCOUNT_START=0 # Optional
export BIPBF_ACCOUNT_END=0 # Optional
export BIPBF_ADDRESS_START=0 # Optional
export BIPBF_ADDRESS_END=0 # Optional
```

#### Or create a .env file:

```
BIPBF_MNEMONIC="your mnemonic phrase"
BIPBF_ADDRESS=your_address
BIPBF_ADDRESS_TYPE=btc-bech32
BIPBF_ACCOUNT_START=0
BIPBF_ACCOUNT_END=0
BIPBF_ADDRESS_START=0
BIPBF_ADDRESS_END=0
```

### Optional Flags

- `--db-path`: Path to SQLite database file (default: "db.sqlite")
- `--workers`: Number of worker threads (default: CPU cores - 1)
- `--batch-size`: Passwords per batch (default: 100000)
- `--cache-size`: Maximum cache size in GB (default: 1gb)
- `--reset-progress`: Reset progress for this run
- `--help`: Show help

## Usage Modes

Specify the brute force mode with `--mode` flag.

If you provide the same params and address configuration as a previous run, the brute force will resume from saved progress. If a run has completed, the program will exit. If a password is found, it will print it to the console and exit. To stop the program, press Ctrl+C.

### 1. Exhaustive Mode

Tries all possible combinations of characters from a charset up to specified length.

Loads charset from `--charset "my charset"`, BIPBF_CHARSET environment variable, or charset.txt in the current directory.

Default is `` abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?` ~``

```bash
# Try all passwords of length 4
bin/bipbf --mode exhaustive --len 4

# Try passwords from length 1-6
bin/bipbf --mode exhaustive --min-len 1 --max-len 6

# With custom charset
bin/bipbf --mode exhaustive --len 4 --charset "abc123"
```

### 2. Password List Mode

Tests passwords from a file.

```bash
# Using passwords.txt (one per line) in current directory
bin/bipbf --mode pwlist

# Using custom password file
bin/bipbf --mode pwlist --pwfile /path/to/passwords.txt
```

### 3. Variation Mode

Generates variations of base passwords by applying character substitutions, deletions, and insertions.

Specify the number of operations to try with `--ops`.

```bash
# Try all 2-character variations a single password
bin/bipbf --mode variation --base "password123" --ops 2

# Try all variations of multiple passwords from passwords.txt
bin/bipbf --mode variation --ops 2
```

### 4. Wordlist Mode

Combines words from a wordlist to create password combinations.

```bash
# Using wordlist.txt (one word per line), combining 2 words
bin/bipbf --mode wordlist --len 2

# With custom separator
bin/bipbf --mode wordlist --len 2 --separator "-"

# Using custom wordlist file
bin/bipbf --mode wordlist --len 2 --wordlist-file /path/to/wordlist.txt
```

## Discord Notifications

To receive progress updates (once per 24h) and success notifications via Discord:

1. Create a Discord webhook URL in your server
2. Set it via environment variable or .env file:

```bash
BIPBF_DISCORD_URL="your-webhook-url"
```

Or use the `--discord-url` flag.

## Recommended Hardware

It is recommended to run on a machine with many cores and a fast CPU to have reasonable performance.

- CPU: 8+ cores at 3+ GHz
- RAM: 8+ GB
- Storage: 100+ GB SSD or NVMe

## License

MIT
