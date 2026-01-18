/**
 * Comprehensive signing functionality tests for all supported chains
 * Tests transaction signing, message signing, signature verification, and address validation
 */

import * as EVM from '../chains/evm';
import * as BTC from '../chains/btc';
import * as Solana from '../chains/solana';
import * as Aptos from '../chains/aptos';
import * as Sui from '../chains/sui';
import * as Tron from '../chains/tron';
import * as Ton from '../chains/ton';
import * as Near from '../chains/near';
import * as Filecoin from '../chains/filecoin';

// Test mnemonic (valid BIP39 12-word phrase)
const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('EVM Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = EVM.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign legacy transaction', () => {
        const tx = {
            to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
            value: '0x0',
            data: '0x',
            nonce: 0,
            gasLimit: '0x5208',
            gasPrice: '0x4a817c800',
            chainId: 1
        };

        const signedTx = EVM.signTransaction(wallet.privateKey, tx);
        expect(signedTx).toBeDefined();
        expect(signedTx).toMatch(/^0x[0-9a-f]+$/i);
    });

    test('should sign EIP-1559 transaction', () => {
        const tx = {
            to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
            value: '0x0',
            data: '0x',
            nonce: 0,
            gasLimit: '0x5208',
            maxFeePerGas: '0x4a817c800',
            maxPriorityFeePerGas: '0x3b9aca00',
            chainId: 1,
            type: 2
        };

        const signedTx = EVM.signTransaction(wallet.privateKey, tx);
        expect(signedTx).toBeDefined();
        expect(signedTx).toMatch(/^0x02[0-9a-f]+$/i);
    });

    test('should sign message', () => {
        const message = 'Hello Ethereum!';
        const signature = EVM.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature.length).toBe(132); // 0x + 130 hex chars (65 bytes)
    });

    test('should verify signature', () => {
        const message = 'Hello Ethereum!';
        const signature = EVM.signMessage(wallet.privateKey, message);

        const isValid = EVM.verifySignature(message, signature, wallet.address);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(EVM.validateAddress(wallet.address)).toBe(true);
        expect(EVM.validateAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0')).toBe(true);
        expect(EVM.validateAddress('invalid')).toBe(false);
        expect(EVM.validateAddress('0x123')).toBe(false);
    });

    test('should convert address to checksum format', () => {
        const checksumAddr = EVM.toChecksumAddress(wallet.address.toLowerCase());
        expect(checksumAddr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    });

    test('should get public key from private key', () => {
        const publicKey = EVM.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('Bitcoin Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        // Use P2PKH for message signing tests (Bitcoin Message Signing standard)
        wallet = BTC.createWallet({ mnemonic: TEST_MNEMONIC, addressType: 'p2pkh' });
    });

    test('should sign message', () => {
        const message = 'Hello Bitcoin!';
        const signature = BTC.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
    });

    test('should verify signature', () => {
        const message = 'Hello Bitcoin!';
        const signature = BTC.signMessage(wallet.privateKey, message);

        const isValid = BTC.verifySignature(message, signature, wallet.address);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(BTC.validateAddress(wallet.address)).toBe(true);
        expect(BTC.validateAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')).toBe(true);
        expect(BTC.validateAddress('invalid')).toBe(false);
    });

    test('should get public key from private key', () => {
        const publicKey = BTC.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('Solana Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Solana.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Solana.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
    });

    test('should sign message', () => {
        const message = 'Hello Solana!';
        const signature = Solana.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(typeof signature).toBe('string');
    });

    test('should verify signature', () => {
        const message = 'Hello Solana!';
        const signature = Solana.signMessage(wallet.privateKey, message);

        const isValid = Solana.verifySignature(message, signature, wallet.publicKey);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(Solana.validateAddress(wallet.address)).toBe(true);
        expect(Solana.validateAddress('11111111111111111111111111111111')).toBe(true);
        expect(Solana.validateAddress('invalid')).toBe(false);
        expect(Solana.validateAddress('too-short')).toBe(false);
    });

    test('should get public key from private key', () => {
        const publicKey = Solana.getPublicKey(wallet.privateKey);
        expect(publicKey).toBeDefined();
        expect(typeof publicKey).toBe('string');
    });
});

describe('Aptos Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Aptos.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Aptos.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^0x[0-9a-f]+$/i);
    });

    test('should sign message', () => {
        const message = 'Hello Aptos!';
        const signature = Aptos.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^0x[0-9a-f]+$/i);
    });

    test('should verify signature', () => {
        const message = 'Hello Aptos!';
        const signature = Aptos.signMessage(wallet.privateKey, message);

        const isValid = Aptos.verifySignature(message, signature, wallet.publicKey);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(Aptos.validateAddress(wallet.address)).toBe(true);
        expect(Aptos.validateAddress('0x1')).toBe(true);
        expect(Aptos.validateAddress('0x' + 'a'.repeat(64))).toBe(true);
        expect(Aptos.validateAddress('invalid')).toBe(false);
    });

    test('should get public key from private key', () => {
        const publicKey = Aptos.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('Sui Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Sui.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction with Bech32 key', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Sui.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should sign message with Bech32 key', () => {
        const message = 'Hello Sui!';
        const signature = Sui.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should verify signature', () => {
        const message = 'Hello Sui!';
        const signature = Sui.signMessage(wallet.privateKey, message);

        const isValid = Sui.verifySignature(message, signature, wallet.publicKey);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(Sui.validateAddress(wallet.address)).toBe(true);
        expect(Sui.validateAddress('0x' + 'a'.repeat(64))).toBe(true);
        expect(Sui.validateAddress('invalid')).toBe(false);
        expect(Sui.validateAddress('0x123')).toBe(false);
    });

    test('should encode and decode Sui private key', () => {
        const decoded = Sui.decodeSuiPrivateKey(wallet.privateKey);
        expect(decoded.secretKey).toBeDefined();
        expect(decoded.secretKey.length).toBe(32);

        const encoded = Sui.encodeSuiPrivateKey(decoded.secretKey);
        expect(encoded).toBe(wallet.privateKey);
    });

    test('should get public key from private key', () => {
        const publicKey = Sui.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('TRON Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Tron.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Tron.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should sign message', () => {
        const message = 'Hello TRON!';
        const signature = Tron.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should verify signature', () => {
        const message = 'Hello TRON!';
        const signature = Tron.signMessage(wallet.privateKey, message);

        const isValid = Tron.verifySignature(message, signature, wallet.address);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(Tron.validateAddress(wallet.address)).toBe(true);
        expect(Tron.validateAddress('TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW')).toBe(true);
        expect(Tron.validateAddress('invalid')).toBe(false);
    });

    test('should get public key from private key', () => {
        const publicKey = Tron.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('TON Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Ton.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Ton.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should sign message', () => {
        const message = 'Hello TON!';
        const signature = Ton.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should verify signature', () => {
        const message = 'Hello TON!';
        const signature = Ton.signMessage(wallet.privateKey, message);

        const isValid = Ton.verifySignature(message, signature, wallet.publicKey);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(Ton.validateAddress(wallet.address)).toBe(true);
        expect(Ton.validateAddress('invalid')).toBe(false);
    });

    test('should get raw address', () => {
        const rawAddr = Ton.getRawAddress(wallet.privateKey);
        expect(rawAddr).toMatch(/^0:[0-9a-f]{64}$/i);
    });

    test('should get public key from private key', () => {
        const publicKey = Ton.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('NEAR Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Near.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Near.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should sign message', () => {
        const message = 'Hello NEAR!';
        const signature = Near.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should verify signature', () => {
        const message = 'Hello NEAR!';
        const signature = Near.signMessage(wallet.privateKey, message);

        const isValid = Near.verifySignature(message, signature, wallet.publicKey);
        expect(isValid).toBe(true);
    });

    test('should validate implicit address', () => {
        expect(Near.validateAddress(wallet.address)).toBe(true);
        expect(Near.validateAddress('a'.repeat(64))).toBe(true);
        expect(Near.validateAddress('invalid')).toBe(false);
    });

    test('should validate named account', () => {
        expect(Near.validateAddress('alice.near')).toBe(true);
        expect(Near.validateAddress('bob.testnet')).toBe(true);
        expect(Near.validateAddress('sub.alice.near')).toBe(true);
        expect(Near.validateAddress('.invalid')).toBe(false);
        expect(Near.validateAddress('invalid.')).toBe(false);
    });

    test('should get public key from private key', () => {
        const publicKey = Near.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('Filecoin Signing Functions', () => {
    let wallet: any;

    beforeAll(() => {
        wallet = Filecoin.createWallet({ mnemonic: TEST_MNEMONIC });
    });

    test('should sign transaction', () => {
        const message = new Uint8Array(32).fill(1); // Mock transaction bytes
        const signature = Filecoin.signTransaction(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should sign message', () => {
        const message = 'Hello Filecoin!';
        const signature = Filecoin.signMessage(wallet.privateKey, message);

        expect(signature).toBeDefined();
        expect(signature).toMatch(/^[0-9a-f]+$/i);
    });

    test('should verify signature', () => {
        const message = 'Hello Filecoin!';
        const signature = Filecoin.signMessage(wallet.privateKey, message);

        const isValid = Filecoin.verifySignature(message, signature, wallet.publicKey);
        expect(isValid).toBe(true);
    });

    test('should validate address', () => {
        expect(Filecoin.validateAddress(wallet.address)).toBe(true);
        expect(Filecoin.validateAddress('f0123')).toBe(true); // ID address
        expect(Filecoin.validateAddress('invalid')).toBe(false);
        expect(Filecoin.validateAddress('t0123')).toBe(true); // Testnet ID address
    });

    test('should get public key from private key', () => {
        const publicKey = Filecoin.getPublicKey(wallet.privateKey);
        expect(publicKey).toBe(wallet.publicKey);
    });
});

describe('Cross-Chain Signature Verification', () => {
    test('should not verify signature with wrong public key', () => {
        const wallet1 = EVM.createWallet();
        const wallet2 = EVM.createWallet();

        const message = 'Test message';
        const signature = EVM.signMessage(wallet1.privateKey, message);

        const isValid = EVM.verifySignature(message, signature, wallet2.publicKey);
        expect(isValid).toBe(false);
    });

    test('should not verify signature with wrong message', () => {
        const wallet = EVM.createWallet();

        const message1 = 'Original message';
        const message2 = 'Different message';
        const signature = EVM.signMessage(wallet.privateKey, message1);

        const isValid = EVM.verifySignature(message2, signature, wallet.publicKey);
        expect(isValid).toBe(false);
    });

    test('should handle invalid signature gracefully', () => {
        const wallet = Solana.createWallet();
        const message = 'Test message';

        const isValid = Solana.verifySignature(message, 'invalid-signature', wallet.publicKey);
        expect(isValid).toBe(false);
    });
});

describe('Address Validation Edge Cases', () => {
    test('should reject empty addresses', () => {
        expect(EVM.validateAddress('')).toBe(false);
        expect(BTC.validateAddress('')).toBe(false);
        expect(Solana.validateAddress('')).toBe(false);
    });

    test('should reject null/undefined addresses', () => {
        expect(EVM.validateAddress(null as any)).toBe(false);
        expect(EVM.validateAddress(undefined as any)).toBe(false);
    });

    test('should handle case sensitivity correctly', () => {
        const evmAddr = '0xABCDEF1234567890ABCDEF1234567890ABCDEF12';
        expect(EVM.validateAddress(evmAddr.toLowerCase())).toBe(true);
        expect(EVM.validateAddress(evmAddr.toUpperCase())).toBe(true);
    });
});
