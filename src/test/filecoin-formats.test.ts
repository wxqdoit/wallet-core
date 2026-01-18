import {
    createWallet,
    getPrivateKeyByMnemonic,
    getAddressByPrivateKey,
    validateAddress,
    signMessage,
    verifySignature,
    getPublicKey
} from "../chains/filecoin";

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('Filecoin Address Formats', () => {
    describe('SECP256K1 (f1) Addresses', () => {
        test('should create secp256k1 wallet', () => {
            const wallet = createWallet({length: 128, addressType: 'secp256k1'});

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^f1[a-z2-7]+$/);
        });

        test('should generate consistent secp256k1 address', () => {
            const {privateKey} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0/0", 'secp256k1');
            const address1 = getAddressByPrivateKey(privateKey, 'secp256k1');
            const address2 = getAddressByPrivateKey(privateKey, 'secp256k1');

            expect(address1).toBe(address2);
            expect(address1).toMatch(/^f1/);
        });

        test('should validate secp256k1 addresses', () => {
            const wallet = createWallet({addressType: 'secp256k1'});
            expect(validateAddress(wallet.address)).toBe(true);

            // Test ID address (f0)
            expect(validateAddress('f0123')).toBe(true);
            expect(validateAddress('f01234567')).toBe(true);
        });

        test('should sign and verify message with secp256k1', () => {
            const wallet = createWallet({addressType: 'secp256k1'});
            const message = 'Hello Filecoin secp256k1!';
            const signature = signMessage(wallet.privateKey, message, 'secp256k1');

            expect(signature).toBeDefined();
            expect(typeof signature).toBe('string');

            const isValid = verifySignature(message, signature, wallet.publicKey!, 'secp256k1');
            expect(isValid).toBe(true);
        });

        test('should get public key from private key (secp256k1)', () => {
            const wallet = createWallet({addressType: 'secp256k1'});
            const publicKey = getPublicKey(wallet.privateKey, 'secp256k1');

            expect(publicKey).toBe(wallet.publicKey);
            expect(publicKey).toBeTruthy();
        });

        test('should default to secp256k1 when no addressType specified', () => {
            const wallet = createWallet({length: 128});
            expect(wallet.address).toMatch(/^f1/);
        });
    });

    describe('BLS (f3) Addresses', () => {
        test('should create BLS wallet', () => {
            const wallet = createWallet({length: 128, addressType: 'bls'});

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^f3[a-z2-7]+$/);
        });

        test('should generate consistent BLS address', () => {
            const {privateKey} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0'/0'", 'bls');
            const address1 = getAddressByPrivateKey(privateKey, 'bls');
            const address2 = getAddressByPrivateKey(privateKey, 'bls');

            expect(address1).toBe(address2);
            expect(address1).toMatch(/^f3/);
        });

        test('should validate BLS addresses', () => {
            const wallet = createWallet({addressType: 'bls'});
            expect(validateAddress(wallet.address)).toBe(true);
        });

        test('should sign and verify message with BLS', () => {
            const wallet = createWallet({addressType: 'bls'});
            const message = 'Hello Filecoin BLS!';
            const signature = signMessage(wallet.privateKey, message, 'bls');

            expect(signature).toBeDefined();
            expect(typeof signature).toBe('string');

            const isValid = verifySignature(message, signature, wallet.publicKey!, 'bls');
            expect(isValid).toBe(true);
        });

        test('should get public key from private key (BLS)', () => {
            const wallet = createWallet({addressType: 'bls'});
            const publicKey = getPublicKey(wallet.privateKey, 'bls');

            expect(publicKey).toBe(wallet.publicKey);
            expect(publicKey).toBeTruthy();
        });
    });

    describe('Cross-format tests', () => {
        test('should generate different addresses for different formats', () => {
            const mnemonic = generateMnemonic(128);
            const secp256k1Wallet = createWallet({mnemonic, addressType: 'secp256k1'});
            const blsWallet = createWallet({mnemonic, addressType: 'bls'});

            expect(secp256k1Wallet.address).not.toBe(blsWallet.address);
            expect(secp256k1Wallet.address).toMatch(/^f1/);
            expect(blsWallet.address).toMatch(/^f3/);

            console.log('SECP256K1 (f1):', secp256k1Wallet.address);
            console.log('BLS (f3):      ', blsWallet.address);
        });

        test('should validate all formats correctly', () => {
            const secp256k1Wallet = createWallet({addressType: 'secp256k1'});
            const blsWallet = createWallet({addressType: 'bls'});

            expect(validateAddress(secp256k1Wallet.address)).toBe(true);
            expect(validateAddress(blsWallet.address)).toBe(true);
        });

        test('should reject invalid addresses', () => {
            expect(validateAddress('invalid')).toBe(false);
            expect(validateAddress('1234567890')).toBe(false);
            expect(validateAddress('f4invalid')).toBe(false); // f4 not implemented
            expect(validateAddress('')).toBe(false);
        });

        test('should not verify signature with wrong addressType', () => {
            const wallet = createWallet({addressType: 'secp256k1'});
            const message = 'Test message';
            const signature = signMessage(wallet.privateKey, message, 'secp256k1');

            // Try to verify with wrong addressType
            const isValid = verifySignature(message, signature, wallet.publicKey!, 'bls');
            expect(isValid).toBe(false);
        });

        test('should handle testnet addresses', () => {
            // Testnet addresses start with 't' instead of 'f'
            expect(validateAddress('t0123')).toBe(true);
            expect(validateAddress('t01234567')).toBe(true); // Fixed: ID addresses are all numeric
        });

        test('should derive same private key from same mnemonic and path (secp256k1)', () => {
            const {privateKey: pk1} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0/0", 'secp256k1');
            const {privateKey: pk2} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0/0", 'secp256k1');

            expect(pk1).toBe(pk2);

            const addr1 = getAddressByPrivateKey(pk1, 'secp256k1');
            const addr2 = getAddressByPrivateKey(pk2, 'secp256k1');
            expect(addr1).toBe(addr2);
        });

        test('should derive same private key from same mnemonic and path (BLS)', () => {
            const {privateKey: pk1} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0'/0'", 'bls');
            const {privateKey: pk2} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0'/0'", 'bls');

            expect(pk1).toBe(pk2);

            const addr1 = getAddressByPrivateKey(pk1, 'bls');
            const addr2 = getAddressByPrivateKey(pk2, 'bls');
            expect(addr1).toBe(addr2);
        });
    });
});

// Helper function for testing
function generateMnemonic(length: 128 | 256): string {
    const bip39 = require('bip39');
    return bip39.generateMnemonic(length);
}
