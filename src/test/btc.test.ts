import {createWallet, getPrivateKeyByMnemonic, getAddressByPrivateKey} from "../chains/btc";

test('Bitcoin wallet creation', () => {
    const wallet = createWallet({length: 128});
    console.log(wallet);

    expect(wallet.mnemonic).toBeTruthy();
    expect(wallet.privateKey).toHaveLength(64);
    expect(wallet.publicKey).toBeTruthy();
    expect(wallet.address).toBeTruthy();
    // Default is now P2WPKH (SegWit)
    expect(wallet.address.startsWith('bc1q')).toBe(true);
});

test('Bitcoin private key derivation from mnemonic', () => {
    const testMnemonic = 'ocean medal extend notice power where require endless shaft tiny dose odor';
    const keys = getPrivateKeyByMnemonic(testMnemonic, "m/44'/0'/0'/0/0");

    expect(keys.privateKey).toHaveLength(64);
    expect(keys.publicKey).toBeTruthy();
});

test('Bitcoin address generation from private key', () => {
    const testPrivateKey = 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807';
    const address = getAddressByPrivateKey(testPrivateKey);

    expect(address).toBeTruthy();
    // Default is now P2WPKH (SegWit)
    expect(address.startsWith('bc1q')).toBe(true);
});

test('Invalid mnemonic throws error', () => {
    expect(() => {
        getPrivateKeyByMnemonic('invalid mnemonic', "m/44'/0'/0'/0/0");
    }).toThrow('Invalid mnemonic');
});

test('Invalid private key length throws error', () => {
    expect(() => {
        getAddressByPrivateKey('invalid');
    }).toThrow('Private key must be 64 hex characters (32 bytes)');
});