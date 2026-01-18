# Wallet Core

A TypeScript-based multi-chain cryptocurrency wallet core library supporting 9+ blockchains with industry-standard BIP39/BIP32/BIP44 implementation.

## Features

- **Multi-Chain Support**: EVM, Bitcoin, Solana, Aptos, Sui, TRON, TON, NEAR, Filecoin
- **BIP Standards**: Full BIP39, BIP32, and BIP44 compliance
- **Type Safety**: Written in TypeScript with full type definitions
- **Modern Crypto**: Built on [@noble](https://github.com/paulmillr/noble-curves) libraries for secure cryptography
- **Tree-Shakeable**: ESM modules for optimal bundle size
- **Well-Tested**: Comprehensive test coverage

## Supported Blockchains

| Blockchain | Curve | Derivation Path | Address Format |
|------------|-------|-----------------|----------------|
| EVM (Ethereum, BSC, Polygon, etc.) | secp256k1 | `m/44'/60'/0'/0/0` | Keccak-256 hash |
| Bitcoin | secp256k1 | `m/44'/0'/0'/0/0` | P2PKH (Base58) |
| Solana | ed25519 | `m/44'/501'/0'/0'` | Base58 |
| Aptos | ed25519 | `m/44'/637'/0'/0'/0'` | SHA3-256 |
| Sui | ed25519 | `m/44'/784'/0'/0'/0'` | Blake2b |
| TRON | secp256k1 | `m/44'/195'/0'/0/0` | Base58Check |
| TON | ed25519 | `m/44'/607'/0'` | Bounce address |
| NEAR | ed25519 | `m/44'/397'/0'` | Base58 |
| Filecoin | ed25519 | `m/44'/461'/0/0/0` | Protocol-specific |

## Installation

```bash
npm install wallet-core
# or
yarn add wallet-core
```

## Quick Start

### Create a New Wallet (EVM Example)

```typescript
import { EVM } from 'wallet-core';

// Create a new wallet with default settings (12-word mnemonic)
const wallet = EVM.createWallet();

console.log(wallet);
// {
//   mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//   privateKey: "0x...",
//   publicKey: "0x...",
//   address: "0x..."
// }
```

### Create Wallet with Custom Options

```typescript
import { BTC } from 'wallet-core';

// Create wallet with 24-word mnemonic and custom derivation path
const wallet = BTC.createWallet({
  length: 256,  // 24 words (default: 128 for 12 words)
  path: "m/44'/0'/0'/0/0"  // Custom derivation path
});
```

### Derive Keys from Existing Mnemonic

```typescript
import { Solana } from 'wallet-core';

const mnemonic = "your twelve word mnemonic phrase here ...";
const derivationPath = "m/44'/501'/0'/0'";

// Get private key from mnemonic
const privateKey = Solana.getPrivateKeyByMnemonic(mnemonic, derivationPath);

// Get address from private key
const address = Solana.getAddressByPrivateKey(privateKey);
```

## API Documentation

### Common Interface

All blockchain modules export the same interface:

```typescript
interface ChainAPI {
  // Create a new wallet
  createWallet(params?: ICreateWallet): IWalletFields;

  // Derive private key from mnemonic
  getPrivateKeyByMnemonic(mnemonic: string, hdPath: string): string | { privateKey: string, publicKey: string };

  // Generate address from private key
  getAddressByPrivateKey(privateKey: string): string;
}

interface ICreateWallet {
  length?: 128 | 256;  // Mnemonic length (12 or 24 words)
  path?: string;       // Custom derivation path
}

interface IWalletFields {
  mnemonic: string;    // BIP39 mnemonic phrase
  privateKey: string;  // Private key (hex or base58)
  publicKey?: string;  // Public key (optional, chain-specific)
  address: string;     // Blockchain address
}
```

### Chain-Specific Examples

#### EVM Chains (Ethereum, BSC, Polygon, etc.)

```typescript
import { EVM } from 'wallet-core';

const wallet = EVM.createWallet();
const keys = EVM.getPrivateKeyByMnemonic(wallet.mnemonic, "m/44'/60'/0'/0/0");
const address = EVM.getAddressByPrivateKey(keys.privateKey);
```

#### Bitcoin

```typescript
import { BTC } from 'wallet-core';

const wallet = BTC.createWallet();
// Address format: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (P2PKH)
```

#### Solana

```typescript
import { Solana } from 'wallet-core';

const wallet = Solana.createWallet();
// Private key is base58 encoded with public key appended
// Address is base58 encoded public key
```

#### Sui

```typescript
import { Sui } from 'wallet-core';

const wallet = Sui.createWallet();

// Sui-specific utilities
const encodedKey = Sui.encodeSuiPrivateKey(privateKeyBytes);
const decoded = Sui.decodeSuiPrivateKey(encodedKey);
```

#### TON

```typescript
import { Ton } from 'wallet-core';

const wallet = Ton.createWallet();

// Get raw address (different format)
const rawAddress = Ton.getRawAddress(wallet.privateKey);
```

### Error Handling

The library exports typed errors for better error handling:

```typescript
import {
  InvalidMnemonicError,
  InvalidPrivateKeyError,
  KeyDerivationError,
  AddressGenerationError
} from 'wallet-core';

try {
  const wallet = EVM.createWallet();
} catch (error) {
  if (error instanceof InvalidMnemonicError) {
    console.error('Invalid mnemonic phrase');
  } else if (error instanceof KeyDerivationError) {
    console.error('Key derivation failed');
  }
}
```

### Available Error Types

- `WalletCoreError` - Base error class
- `InvalidMnemonicError` - Mnemonic validation failed
- `InvalidPrivateKeyError` - Invalid private key format
- `KeyDerivationError` - Key derivation failed
- `AddressGenerationError` - Address generation failed
- `PrivateKeyEncodingError` - Encoding/decoding failed
- `InvalidParameterError` - Invalid function parameter

## Security Best Practices

1. **Never expose private keys or mnemonics** in client-side code or logs
2. **Use environment variables** for sensitive data in production
3. **Validate user input** before processing
4. **Use secure random number generation** (library handles this internally)
5. **Store mnemonics encrypted** when persisting to disk
6. **Never commit** mnemonics or private keys to version control

## Development

### Setup

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage

# Build the project
npm run build

# Build in watch mode
npm run build:watch

# Clean build artifacts
npm run clean
```

### Project Structure

```
wallet-core/
├── src/
│   ├── chains/           # Blockchain implementations
│   │   ├── aptos.ts
│   │   ├── btc.ts
│   │   ├── evm.ts
│   │   ├── filecoin.ts
│   │   ├── near.ts
│   │   ├── solana.ts
│   │   ├── sui.ts
│   │   ├── ton.ts
│   │   └── tron.ts
│   ├── base/             # Base conversion utilities
│   ├── utils/            # Utility functions
│   ├── errors/           # Custom error types
│   ├── types/            # TypeScript type definitions
│   ├── constans/         # Constants (derivation paths, etc.)
│   └── index.ts          # Main entry point
├── dist/                 # Compiled output (generated)
├── package.json
├── tsconfig.json
└── jest.config.js
```

## Dependencies

### Core Cryptography
- `@noble/curves` - Elliptic curve cryptography
- `@noble/hashes` - Cryptographic hash functions
- `@scure/bip32` - HD key derivation
- `bip39` - Mnemonic generation and validation

### Chain-Specific
- `bitcoinjs-lib` - Bitcoin utilities
- `bs58` - Base58 encoding

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing

The project uses Jest for testing. Test files are located in `src/test/`:

### Unit Tests
- `aptos.test.ts` - Aptos chain tests
- `btc.test.ts` - Bitcoin tests
- `evm.test.ts` - EVM chains tests
- `near.test.ts` - NEAR tests
- `solana.test.ts` - Solana tests
- `sui.test.ts` - Sui tests
- `ton.test.ts` - TON tests
- `tron.test.ts` - TRON tests
- `private-key-validation.test.ts` - Private key validation for all chains
- `signing.test.ts` - Transaction signing tests
- `all-chains.test.ts` - Cross-chain consistency tests

### Integration Tests (Testnet)

Integration tests verify wallet functionality against real testnets. These tests are **skipped by default** to avoid requiring testnet funds.

#### Running Integration Tests

```bash
# Enable integration tests
RUN_INTEGRATION=true npm test src/test/integration.test.ts
```

#### Setting Up for Integration Tests

1. **Get Test Addresses**: Run the address generator
   ```bash
   npm test src/test/generate-addresses.test.ts
   ```

2. **Fund Test Wallets**: Follow the [Testnet Guide](TESTNET_GUIDE.md) to get test tokens:
   - Ethereum Sepolia: https://sepoliafaucet.com/
   - Bitcoin Testnet: https://testnet-faucet.mempool.co/
   - Solana Devnet: https://faucet.solana.com/
   - Aptos Devnet: https://aptoslabs.com/testnet-faucet
   - And more...

3. **Run Tests**:
   ```bash
   RUN_INTEGRATION=true npm test src/test/integration.test.ts
   ```

**Note**: The test mnemonic and addresses are public (for testnet only). Never use them on mainnet!

## License

ISC License - see LICENSE file for details

## Disclaimer

This library is provided as-is for educational and development purposes. Always audit the code and conduct security reviews before using in production with real funds. The authors are not responsible for any loss of funds.

## Resources

- [BIP39 - Mnemonic Code](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 - Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP44 - Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [@noble/curves](https://github.com/paulmillr/noble-curves)

## Support

For questions, issues, or feature requests, please open an issue on GitHub.

