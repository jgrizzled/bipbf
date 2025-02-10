# bipbf

**bipbf** is a brute force tool for recovering wallets where you have the seed phrase and a known address but forgot the password (aka 25th word).

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

3. **Run the Application:**

   ```bash
   export BIPBF_MNEMONIC="your mnemonic phrase"
   export BIPBF_ADDRESS="your address"
   export BIPBF_ADDRESS_TYPE="btc-nativesegwit" # or "eth"
   ./bin/bipbf --naive --maxLen 5
   ```

## License

MIT
