import {createWallet, getPrivateKeyByMnemonic, getAddressByPrivateKey, validateAddress} from "../chains/btc";

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TEST_PRIVATE_KEY = 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807';

describe('Bitcoin Address Formats', () => {
    describe('P2PKH (Legacy) - starts with 1', () => {
        test('should create P2PKH wallet', () => {
            const wallet = createWallet({length: 128, addressType: 'p2pkh'});

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/);
        });

        test('should generate consistent P2PKH address', () => {
            const address1 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2pkh');
            const address2 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2pkh');

            expect(address1).toBe(address2);
            expect(address1).toMatch(/^1/);
        });

        test('should validate P2PKH addresses', () => {
            const address = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2pkh');
            expect(validateAddress(address)).toBe(true);

            // Known P2PKH addresses
            expect(validateAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')).toBe(true);
            expect(validateAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')).toBe(true);
        });
    });

    describe('P2SH (Script Hash) - starts with 3', () => {
        test('should create P2SH wallet', () => {
            const wallet = createWallet({length: 128, addressType: 'p2sh'});

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/);
        });

        test('should generate consistent P2SH address', () => {
            const address1 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2sh');
            const address2 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2sh');

            expect(address1).toBe(address2);
            expect(address1).toMatch(/^3/);
        });

        test('should validate P2SH addresses', () => {
            const address = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2sh');
            expect(validateAddress(address)).toBe(true);

            // Test another generated P2SH address
            const {privateKey} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/0'/0'/0/0");
            const address2 = getAddressByPrivateKey(privateKey, 'p2sh');
            expect(validateAddress(address2)).toBe(true);
            expect(address2).toMatch(/^3/);
        });
    });

    describe('P2WPKH (Native SegWit) - starts with bc1q', () => {
        test('should create P2WPKH wallet', () => {
            const wallet = createWallet({length: 128, addressType: 'p2wpkh'});

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^bc1q[a-z0-9]{38,58}$/);
        });

        test('should generate consistent P2WPKH address', () => {
            const address1 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2wpkh');
            const address2 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2wpkh');

            expect(address1).toBe(address2);
            expect(address1).toMatch(/^bc1q/);
        });

        test('should validate P2WPKH addresses', () => {
            const address = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2wpkh');
            expect(validateAddress(address)).toBe(true);

            // Known P2WPKH addresses
            expect(validateAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toBe(true);
            expect(validateAddress('bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3')).toBe(true);
        });

        test('should default to P2WPKH when no addressType specified', () => {
            const wallet = createWallet({length: 128});
            expect(wallet.address).toMatch(/^bc1q/);
        });
    });

    describe('P2TR (Taproot) - starts with bc1p', () => {
        test('should create P2TR wallet', () => {
            const wallet = createWallet({length: 128, addressType: 'p2tr'});

            expect(wallet.mnemonic).toBeTruthy();
            expect(wallet.privateKey).toHaveLength(64);
            expect(wallet.publicKey).toBeTruthy();
            expect(wallet.address).toMatch(/^bc1p[a-z0-9]{58}$/);
        });

        test('should generate consistent P2TR address', () => {
            const address1 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2tr');
            const address2 = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2tr');

            expect(address1).toBe(address2);
            expect(address1).toMatch(/^bc1p/);
        });

        test('should validate P2TR addresses', () => {
            const address = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2tr');
            expect(validateAddress(address)).toBe(true);
        });
    });

    describe('Cross-format tests', () => {
        test('should generate different addresses for different formats', () => {
            const p2pkh = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2pkh');
            const p2sh = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2sh');
            const p2wpkh = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2wpkh');
            const p2tr = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2tr');

            // All addresses should be different
            expect(p2pkh).not.toBe(p2sh);
            expect(p2pkh).not.toBe(p2wpkh);
            expect(p2pkh).not.toBe(p2tr);
            expect(p2sh).not.toBe(p2wpkh);
            expect(p2sh).not.toBe(p2tr);
            expect(p2wpkh).not.toBe(p2tr);

            console.log('P2PKH:  ', p2pkh);
            console.log('P2SH:   ', p2sh);
            console.log('P2WPKH: ', p2wpkh);
            console.log('P2TR:   ', p2tr);
        });

        test('should validate all formats correctly', () => {
            const p2pkh = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2pkh');
            const p2sh = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2sh');
            const p2wpkh = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2wpkh');
            const p2tr = getAddressByPrivateKey(TEST_PRIVATE_KEY, 'p2tr');

            expect(validateAddress(p2pkh)).toBe(true);
            expect(validateAddress(p2sh)).toBe(true);
            expect(validateAddress(p2wpkh)).toBe(true);
            expect(validateAddress(p2tr)).toBe(true);
        });

        test('should reject invalid addresses', () => {
            expect(validateAddress('invalid')).toBe(false);
            expect(validateAddress('1234567890')).toBe(false);
            expect(validateAddress('bc1invalid')).toBe(false);
            expect(validateAddress('')).toBe(false);
        });

        test('should derive same private key from mnemonic for all formats', () => {
            const {privateKey: pk1} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/0'/0'/0/0");
            const {privateKey: pk2} = getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/0'/0'/0/0");

            expect(pk1).toBe(pk2);

            // All address formats should work with the same private key
            const p2pkh = getAddressByPrivateKey(pk1, 'p2pkh');
            const p2sh = getAddressByPrivateKey(pk1, 'p2sh');
            const p2wpkh = getAddressByPrivateKey(pk1, 'p2wpkh');
            const p2tr = getAddressByPrivateKey(pk1, 'p2tr');

            expect(validateAddress(p2pkh)).toBe(true);
            expect(validateAddress(p2sh)).toBe(true);
            expect(validateAddress(p2wpkh)).toBe(true);
            expect(validateAddress(p2tr)).toBe(true);
        });
    });
});
