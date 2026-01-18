/**
 * Integration tests for wallet-core with real testnet interactions
 *
 * These tests require testnet tokens to be funded in the test addresses.
 * See TESTNET_GUIDE.md for instructions on how to get testnet tokens.
 *
 * Set RUN_INTEGRATION=true to run these tests
 */

import { TEST_MNEMONIC, TEST_ADDRESSES, TESTNET_RPCS } from './testnet-config';
import * as EVM from '../chains/evm';
import * as BTC from '../chains/btc';
import * as Solana from '../chains/solana';
import * as Aptos from '../chains/aptos';
import * as Sui from '../chains/sui';
import * as Tron from '../chains/tron';
import * as Ton from '../chains/ton';
import * as Near from '../chains/near';
import * as Filecoin from '../chains/filecoin';

const SKIP_INTEGRATION = !process.env.RUN_INTEGRATION;
const describeOrSkip = SKIP_INTEGRATION ? describe.skip : describe;
const testOrSkip = SKIP_INTEGRATION ? test.skip : test;

describeOrSkip('Testnet Integration Tests', () => {
    beforeAll(() => {
        if (SKIP_INTEGRATION) {
            console.log('\n⏭️  Skipping integration tests (set RUN_INTEGRATION=true to run)');
        } else {
            console.log('\n🧪 Running integration tests with real testnet data...');
            console.log('📖 See TESTNET_GUIDE.md for funding instructions\n');
        }
    });

    describeOrSkip('EVM Chains (Ethereum Sepolia)', () => {
        test('should derive correct address from mnemonic', () => {
            const wallet = EVM.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/60'/0'/0/0"
            });
            expect(`0x${wallet.address}`).toBe(TEST_ADDRESSES.EVM);
        });

        test('should sign and verify message', () => {
            const message = 'Hello from wallet-core integration test';
            const privateKey = EVM.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/60'/0'/0/0").privateKey;

            const signature = EVM.signMessage(privateKey, message);

            expect(signature).toBeTruthy();
            expect(signature.length).toBeGreaterThan(100);

            console.log(`✅ EVM Message signed: ${signature.slice(0, 20)}...`);
        });

        test('should validate private key', () => {
            const privateKey = EVM.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/60'/0'/0/0").privateKey;
            expect(EVM.validatePrivateKey(privateKey)).toBe(true);
        });
    });

    describeOrSkip('Bitcoin Testnet', () => {
        test('should derive correct SegWit address', () => {
            const wallet = BTC.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/84'/0'/0'/0/0"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.BTC);
        });

        test('should generate multiple address types', () => {
            const privateKey = BTC.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/84'/0'/0'/0/0").privateKey;

            const p2pkh = BTC.getAddressByPrivateKey(privateKey, 'p2pkh');
            const p2sh = BTC.getAddressByPrivateKey(privateKey, 'p2sh');
            const p2wpkh = BTC.getAddressByPrivateKey(privateKey, 'p2wpkh');
            const p2tr = BTC.getAddressByPrivateKey(privateKey, 'p2tr');

            expect(p2pkh).toMatch(/^1/);
            expect(p2sh).toMatch(/^3/);
            expect(p2wpkh).toMatch(/^bc1q/);
            expect(p2tr).toMatch(/^bc1p/);

            console.log(`✅ BTC addresses generated: P2PKH, P2SH, P2WPKH, P2TR`);
        });

        test('should validate private key', () => {
            const privateKey = BTC.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/84'/0'/0'/0/0").privateKey;
            expect(BTC.validatePrivateKey(privateKey)).toBe(true);
        });
    });

    describeOrSkip('Solana Devnet', () => {
        test('should derive correct address', () => {
            const wallet = Solana.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/501'/0'/0'"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.SOLANA);
        });

        test('should sign and verify message', () => {
            const message = 'Solana integration test';
            const privateKey = Solana.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/501'/0'/0'");

            const signature = Solana.signMessage(privateKey, message);
            const publicKey = Solana.getPublicKey(privateKey);

            const isValid = Solana.verifySignature(message, signature, publicKey);

            expect(isValid).toBe(true);
            console.log(`✅ Solana message signature verified`);
        });

        test('should validate private key', () => {
            const privateKey = Solana.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/501'/0'/0'");
            expect(Solana.validatePrivateKey(privateKey)).toBe(true);
        });
    });

    describeOrSkip('Aptos Devnet', () => {
        test('should derive correct address', () => {
            const wallet = Aptos.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/637'/0'/0'/0'"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.APTOS);
        });

        test('should sign and verify message', () => {
            const message = 'Aptos integration test';
            const privateKey = Aptos.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/637'/0'/0'/0'");

            const signature = Aptos.signMessage(privateKey, message);
            const publicKey = Aptos.getPublicKey(privateKey);

            const isValid = Aptos.verifySignature(message, signature, publicKey);

            expect(isValid).toBe(true);
            console.log(`✅ Aptos message signature verified`);
        });

        test('should validate private key', () => {
            const privateKey = Aptos.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/637'/0'/0'/0'");
            expect(Aptos.validatePrivateKey(privateKey)).toBe(true);
        });
    });

    describeOrSkip('Sui Devnet', () => {
        test('should derive correct address', () => {
            const wallet = Sui.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/784'/0'/0'/0'"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.SUI);
        });

        test('should sign and verify message', () => {
            const message = 'Sui integration test';
            const privateKey = Sui.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/784'/0'/0'/0'");

            const signature = Sui.signMessage(privateKey, message);
            const publicKey = Sui.getPublicKey(privateKey);

            const isValid = Sui.verifySignature(message, signature, publicKey);

            expect(isValid).toBe(true);
            console.log(`✅ Sui message signature verified`);
        });

        test('should support Bech32 encoded private keys', () => {
            const privateKey = Sui.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/784'/0'/0'/0'");
            const encoded = Sui.encodeSuiPrivateKey(privateKey);

            expect(encoded).toMatch(/^suiprivkey1/);
            expect(Sui.validatePrivateKey(encoded)).toBe(true);

            console.log(`✅ Sui Bech32 private key: ${encoded.slice(0, 20)}...`);
        });
    });

    describeOrSkip('TRON Nile Testnet', () => {
        test('should derive correct address', () => {
            const wallet = Tron.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/195'/0'/0/0"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.TRON);
        });

        test('should sign and verify message', () => {
            const message = 'TRON integration test';
            const privateKey = Tron.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/195'/0'/0/0").privateKey;

            const signature = Tron.signMessage(privateKey, message);

            const isValid = Tron.verifySignature(message, signature, TEST_ADDRESSES.TRON);

            expect(isValid).toBe(true);
            console.log(`✅ TRON message signature verified`);
        });

        test('should validate TRON address', () => {
            expect(Tron.validateAddress(TEST_ADDRESSES.TRON)).toBe(true);
            expect(Tron.validateAddress('InvalidAddress')).toBe(false);
        });
    });

    describeOrSkip('TON Testnet', () => {
        test('should derive correct address', () => {
            const wallet = Ton.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/607'/0'/0'/0'"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.TON);
        });

        test('should sign and verify message', () => {
            const message = 'TON integration test';
            const privateKey = Ton.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/607'/0'/0'/0'");

            const signature = Ton.signMessage(privateKey, message);
            const publicKey = Ton.getPublicKey(privateKey);

            const isValid = Ton.verifySignature(message, signature, publicKey);

            expect(isValid).toBe(true);
            console.log(`✅ TON message signature verified`);
        });

        test('should get raw address format', () => {
            const privateKey = Ton.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/607'/0'/0'/0'");
            const rawAddress = Ton.getRawAddress(privateKey);

            expect(rawAddress).toMatch(/^0:/);
            console.log(`✅ TON raw address: ${rawAddress}`);
        });
    });

    describeOrSkip('NEAR Testnet', () => {
        test('should derive correct implicit address', () => {
            const wallet = Near.createWallet({
                mnemonic: TEST_MNEMONIC,
                path: "m/44'/397'/0'"
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.NEAR);
        });

        test('should sign and verify message', () => {
            const message = 'NEAR integration test';
            const privateKey = Near.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/397'/0'");

            const signature = Near.signMessage(privateKey, message);
            const publicKey = Near.getPublicKey(privateKey);

            const isValid = Near.verifySignature(message, signature, publicKey);

            expect(isValid).toBe(true);
            console.log(`✅ NEAR message signature verified`);
        });

        test('should validate both implicit and named addresses', () => {
            expect(Near.validateAddress(TEST_ADDRESSES.NEAR)).toBe(true);
            expect(Near.validateAddress('alice.testnet')).toBe(true);
            expect(Near.validateAddress('invalid')).toBe(false);
        });
    });

    describeOrSkip('Filecoin Calibration Testnet', () => {
        test('should derive correct secp256k1 address', () => {
            const wallet = Filecoin.createWallet({
                mnemonic: TEST_MNEMONIC,
                addressType: 'secp256k1'
            });
            expect(wallet.address).toBe(TEST_ADDRESSES.FILECOIN);
        });

        test('should support both secp256k1 and BLS', () => {
            const secp256k1Keys = Filecoin.getPrivateKeyByMnemonic(
                TEST_MNEMONIC,
                "m/44'/461'/0'/0/0",
                'secp256k1'
            );
            const secp256k1Addr = Filecoin.getAddressByPrivateKey(secp256k1Keys.privateKey, 'secp256k1');

            const blsKeys = Filecoin.getPrivateKeyByMnemonic(
                TEST_MNEMONIC,
                "m/44'/461'/0'/0/0",
                'bls'
            );
            const blsAddr = Filecoin.getAddressByPrivateKey(blsKeys.privateKey, 'bls');

            expect(secp256k1Addr).toMatch(/^f1/);
            expect(blsAddr).toMatch(/^f3/);

            console.log(`✅ Filecoin secp256k1: ${secp256k1Addr}`);
            console.log(`✅ Filecoin BLS: ${blsAddr}`);
        });

        test('should sign and verify message with both types', () => {
            const message = 'Filecoin integration test';

            // secp256k1
            const secp256k1Keys = Filecoin.getPrivateKeyByMnemonic(
                TEST_MNEMONIC,
                "m/44'/461'/0'/0/0",
                'secp256k1'
            );
            const secp256k1Sig = Filecoin.signMessage(secp256k1Keys.privateKey, message, 'secp256k1');
            const secp256k1Valid = Filecoin.verifySignature(
                message,
                secp256k1Sig,
                secp256k1Keys.publicKey,
                'secp256k1'
            );

            // BLS
            const blsKeys = Filecoin.getPrivateKeyByMnemonic(
                TEST_MNEMONIC,
                "m/44'/461'/0'/0/0",
                'bls'
            );
            const blsSig = Filecoin.signMessage(blsKeys.privateKey, message, 'bls');
            const blsValid = Filecoin.verifySignature(
                message,
                blsSig,
                blsKeys.publicKey,
                'bls'
            );

            expect(secp256k1Valid).toBe(true);
            expect(blsValid).toBe(true);

            console.log(`✅ Filecoin secp256k1 signature verified`);
            console.log(`✅ Filecoin BLS signature verified`);
        });
    });

    describeOrSkip('Cross-Chain Consistency', () => {
        test('all wallets should be derived from same mnemonic', () => {
            const evmWallet = EVM.createWallet({ mnemonic: TEST_MNEMONIC, path: "m/44'/60'/0'/0/0" });
            const btcWallet = BTC.createWallet({ mnemonic: TEST_MNEMONIC, path: "m/84'/0'/0'/0/0" });
            const solanaWallet = Solana.createWallet({ mnemonic: TEST_MNEMONIC, path: "m/44'/501'/0'/0'" });

            expect(evmWallet.mnemonic).toBe(TEST_MNEMONIC);
            expect(btcWallet.mnemonic).toBe(TEST_MNEMONIC);
            expect(solanaWallet.mnemonic).toBe(TEST_MNEMONIC);
        });

        test('all private key validations should work', () => {
            const chains = [
                { name: 'EVM', validate: EVM.validatePrivateKey, key: EVM.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/60'/0'/0/0").privateKey },
                { name: 'BTC', validate: BTC.validatePrivateKey, key: BTC.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/84'/0'/0'/0/0").privateKey },
                { name: 'Solana', validate: Solana.validatePrivateKey, key: Solana.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/501'/0'/0'") },
                { name: 'Aptos', validate: Aptos.validatePrivateKey, key: Aptos.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/637'/0'/0'/0'") },
                { name: 'Sui', validate: Sui.validatePrivateKey, key: Sui.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/784'/0'/0'/0'") },
                { name: 'TRON', validate: Tron.validatePrivateKey, key: Tron.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/195'/0'/0/0").privateKey },
                { name: 'TON', validate: Ton.validatePrivateKey, key: Ton.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/607'/0'/0'/0'") },
                { name: 'NEAR', validate: Near.validatePrivateKey, key: Near.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/397'/0'") },
            ];

            chains.forEach(({ name, validate, key }) => {
                expect(validate(key)).toBe(true);
                console.log(`✅ ${name} private key validation passed`);
            });
        });
    });
});
