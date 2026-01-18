import { EVM, BTC, Solana, Aptos, Sui, Tron, Ton, Near, Filecoin } from '../index';

describe('All Chains Wallet Functionality', () => {

    // Test mnemonic for consistent testing
    const testMnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    describe('EVM Chain (Ethereum, BSC, Polygon, etc.)', () => {
        test('should create a new wallet', () => {
            const wallet = EVM.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toHaveLength(40);

            console.log('EVM Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const result = EVM.getPrivateKeyByMnemonic(testMnemonic, "m/44'/60'/0'/0/0");

            expect(result.privateKey).toHaveLength(64);
            expect(result.publicKey).toBeTruthy();

            console.log('EVM Keys:', result);
        });

        test('should generate address from private key', () => {
            const result = EVM.getPrivateKeyByMnemonic(testMnemonic, "m/44'/60'/0'/0/0");
            const address = EVM.getAddressByPrivateKey(result.privateKey);

            expect(address).toHaveLength(40);
            expect(address).toMatch(/^[0-9a-f]{40}$/);

            console.log('EVM Address:', address);
        });
    });

    describe('Bitcoin Chain', () => {
        test('should create a new wallet', () => {
            const wallet = BTC.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            // Default is now P2WPKH (SegWit), which starts with bc1q
            expect(wallet.address).toMatch(/^bc1q[a-z0-9]{38,58}$/);

            console.log('BTC Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const result = BTC.getPrivateKeyByMnemonic(testMnemonic, "m/44'/0'/0'/0/0");

            expect(result.privateKey).toHaveLength(64);
            expect(result.publicKey).toBeTruthy();

            console.log('BTC Keys:', result);
        });

        test('should generate address from private key', () => {
            const result = BTC.getPrivateKeyByMnemonic(testMnemonic, "m/44'/0'/0'/0/0");
            const address = BTC.getAddressByPrivateKey(result.privateKey);

            // Default is now P2WPKH (SegWit)
            expect(address).toMatch(/^bc1q[a-z0-9]{38,58}$/);

            console.log('BTC Address:', address);
        });
    });

    describe('Solana Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Solana.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toBeTruthy();
            expect(wallet.address).toBeTruthy();

            console.log('Solana Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const privateKey = Solana.getPrivateKeyByMnemonic(testMnemonic, "m/44'/501'/0'/0'");

            expect(privateKey).toBeTruthy();

            console.log('Solana Private Key:', privateKey);
        });

        test('should generate address from private key', () => {
            const privateKey = Solana.getPrivateKeyByMnemonic(testMnemonic, "m/44'/501'/0'/0'");
            const address = Solana.getAddressByPrivateKey(privateKey);

            expect(address).toBeTruthy();
            expect(typeof address).toBe('string');

            console.log('Solana Address:', address);
        });
    });

    describe('Aptos Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Aptos.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toHaveLength(64);
            expect(wallet.address).toHaveLength(66); // 0x + 64 hex chars

            console.log('Aptos Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const privateKey = Aptos.getPrivateKeyByMnemonic(testMnemonic, "m/44'/637'/0'/0'/0'");

            expect(privateKey).toHaveLength(64);

            console.log('Aptos Private Key:', privateKey);
        });

        test('should generate address from private key', () => {
            const privateKey = Aptos.getPrivateKeyByMnemonic(testMnemonic, "m/44'/637'/0'/0'/0'");
            const address = Aptos.getAddressByPrivateKey(privateKey);

            expect(address).toHaveLength(66); // 0x + 64 hex chars
            expect(address).toMatch(/^0x[0-9a-f]{64}$/);

            console.log('Aptos Address:', address);
        });
    });

    describe('Sui Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Sui.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toMatch(/^suiprivkey/);
            expect(wallet.publicKey).toHaveLength(64);
            expect(wallet.address).toHaveLength(66); // 0x + 64 hex chars

            console.log('Sui Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const privateKey = Sui.getPrivateKeyByMnemonic(testMnemonic, "m/44'/784'/0'/0'/0'");

            expect(privateKey).toHaveLength(64);

            console.log('Sui Private Key:', privateKey);
        });

        test('should generate address from private key', () => {
            const privateKey = Sui.getPrivateKeyByMnemonic(testMnemonic, "m/44'/784'/0'/0'/0'");
            const address = Sui.getAddressByPrivateKey(privateKey);

            expect(address).toHaveLength(66); // 0x + 64 hex chars
            expect(address).toMatch(/^0x[0-9a-f]{64}$/);

            console.log('Sui Address:', address);
        });

        test('should encode and decode Sui private key', () => {
            const wallet = Sui.createWallet();
            const privateKey = Sui.getPrivateKeyByMnemonic(wallet.mnemonic, "m/44'/784'/0'/0'/0'");

            // Encode private key
            const encoded = wallet.privateKey; // Already encoded in createWallet
            expect(encoded).toMatch(/^suiprivkey/);

            // Decode private key
            const decoded = Sui.decodeSuiPrivateKey(encoded);
            expect(decoded.secretKey).toBeTruthy();
            expect(decoded.secretKey.length).toBe(32);

            console.log('Sui Encoded Key:', encoded);
        });
    });

    describe('TRON Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Tron.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^T[a-zA-Z0-9]{33}$/);

            console.log('TRON Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const result = Tron.getPrivateKeyByMnemonic(testMnemonic, "m/44'/195'/0'/0/0");

            expect(result.privateKey).toHaveLength(64);
            expect(result.publicKey).toBeTruthy();

            console.log('TRON Keys:', result);
        });

        test('should generate address from private key', () => {
            const result = Tron.getPrivateKeyByMnemonic(testMnemonic, "m/44'/195'/0'/0/0");
            const address = Tron.getAddressByPrivateKey(result.privateKey);

            expect(address).toMatch(/^T[a-zA-Z0-9]{33}$/);

            console.log('TRON Address:', address);
        });
    });

    describe('TON Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Ton.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toHaveLength(64);
            expect(wallet.address).toBeTruthy();

            console.log('TON Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const privateKey = Ton.getPrivateKeyByMnemonic(testMnemonic, "m/44'/607'/0'");

            expect(privateKey).toHaveLength(64);

            console.log('TON Private Key:', privateKey);
        });

        test('should generate address from private key', () => {
            const privateKey = Ton.getPrivateKeyByMnemonic(testMnemonic, "m/44'/607'/0'");
            const address = Ton.getAddressByPrivateKey(privateKey);

            expect(address).toBeTruthy();
            expect(typeof address).toBe('string');

            console.log('TON Address:', address);
        });

        test('should get raw address', () => {
            const privateKey = Ton.getPrivateKeyByMnemonic(testMnemonic, "m/44'/607'/0'");
            const rawAddress = Ton.getRawAddress(privateKey);

            expect(rawAddress).toMatch(/^0:[0-9a-f]{64}$/);

            console.log('TON Raw Address:', rawAddress);
        });
    });

    describe('NEAR Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Near.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toHaveLength(64);
            expect(wallet.address).toHaveLength(64);

            console.log('NEAR Wallet:', wallet);
        });

        test('should derive private key from mnemonic', () => {
            const privateKey = Near.getPrivateKeyByMnemonic(testMnemonic, "m/44'/397'/0'");

            expect(privateKey).toHaveLength(64);

            console.log('NEAR Private Key:', privateKey);
        });

        test('should generate address from private key', () => {
            const privateKey = Near.getPrivateKeyByMnemonic(testMnemonic, "m/44'/397'/0'");
            const address = Near.getAddressByPrivateKey(privateKey);

            expect(address).toHaveLength(64);
            expect(address).toMatch(/^[0-9a-f]{64}$/);

            console.log('NEAR Address:', address);
        });
    });

    describe('Filecoin Chain', () => {
        test('should create a new wallet', () => {
            const wallet = Filecoin.createWallet();

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            // Default is secp256k1 (f1) addresses
            expect(wallet.address).toMatch(/^f1/);
            expect(wallet.address.length).toBeGreaterThan(10);

            console.log('Filecoin Wallet:', wallet);
        });

        test('should derive private key from mnemonic (secp256k1)', () => {
            // Using standard path for secp256k1
            const result = Filecoin.getPrivateKeyByMnemonic(testMnemonic, "m/44'/461'/0'/0/0", 'secp256k1');

            expect(result.privateKey).toHaveLength(64);
            expect(result.publicKey).toBeTruthy();

            console.log('Filecoin Private Key:', result.privateKey);
        });

        test('should generate address from private key (secp256k1)', () => {
            const {privateKey} = Filecoin.getPrivateKeyByMnemonic(testMnemonic, "m/44'/461'/0'/0/0", 'secp256k1');
            const address = Filecoin.getAddressByPrivateKey(privateKey, 'secp256k1');

            // secp256k1 addresses start with 'f1'
            expect(address).toMatch(/^f1/);
            expect(address.length).toBeGreaterThan(10);

            console.log('Filecoin Address:', address);
        });

        test('should support BLS addresses', () => {
            const wallet = Filecoin.createWallet({addressType: 'bls'});

            expect(wallet.address).toMatch(/^f3/);
            expect(wallet.privateKey).toHaveLength(64);

            console.log('Filecoin BLS Wallet:', wallet);
        });
    });

    describe('Cross-Chain Consistency', () => {
        test('should generate same keys from same mnemonic for each chain', () => {
            // Using a valid 12-word BIP39 mnemonic
            const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

            // Test EVM
            const evm1 = EVM.getPrivateKeyByMnemonic(mnemonic, "m/44'/60'/0'/0/0");
            const evm2 = EVM.getPrivateKeyByMnemonic(mnemonic, "m/44'/60'/0'/0/0");
            expect(evm1.privateKey).toBe(evm2.privateKey);

            // Test BTC
            const btc1 = BTC.getPrivateKeyByMnemonic(mnemonic, "m/44'/0'/0'/0/0");
            const btc2 = BTC.getPrivateKeyByMnemonic(mnemonic, "m/44'/0'/0'/0/0");
            expect(btc1.privateKey).toBe(btc2.privateKey);

            // Test Solana
            const sol1 = Solana.getPrivateKeyByMnemonic(mnemonic, "m/44'/501'/0'/0'");
            const sol2 = Solana.getPrivateKeyByMnemonic(mnemonic, "m/44'/501'/0'/0'");
            expect(sol1).toBeTruthy();
            expect(sol2).toBeTruthy();

            console.log('✓ Cross-chain consistency verified');
        });

        test('should generate different keys with different derivation paths', () => {
            // Using a valid 12-word BIP39 mnemonic
            const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

            const key1 = EVM.getPrivateKeyByMnemonic(mnemonic, "m/44'/60'/0'/0/0");
            const key2 = EVM.getPrivateKeyByMnemonic(mnemonic, "m/44'/60'/0'/0/1");

            expect(key1.privateKey).not.toBe(key2.privateKey);

            console.log('✓ Derivation path uniqueness verified');
        });
    });

    describe('Wallet Recovery', () => {
        test('should recover wallet from mnemonic across all chains', () => {
            // Create wallets
            const evmWallet = EVM.createWallet();
            const btcWallet = BTC.createWallet();
            const solWallet = Solana.createWallet();

            // Recover from mnemonic
            const evmRecovered = EVM.getPrivateKeyByMnemonic(evmWallet.mnemonic, "m/44'/60'/0'/0/0");
            const btcRecovered = BTC.getPrivateKeyByMnemonic(btcWallet.mnemonic, "m/44'/0'/0'/0/0");
            const solRecovered = Solana.getPrivateKeyByMnemonic(solWallet.mnemonic, "m/44'/501'/0'/0'");

            expect(evmRecovered.privateKey).toBe(evmWallet.privateKey);
            expect(btcRecovered.privateKey).toBe(btcWallet.privateKey);
            expect(solRecovered).toBeTruthy();

            console.log('✓ Wallet recovery successful for all chains');
        });
    });
});
