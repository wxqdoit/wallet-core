import {createWallet, getPrivateKeyByMnemonic, getAddressByPrivateKey} from "../chains/near";

test('Near wallet creation', () => {
    const wallet = createWallet({length: 128});
    console.log(wallet);

    expect(wallet.mnemonic).toBeTruthy();
    expect(wallet.privateKey).toHaveLength(64);
    expect(wallet.publicKey).toHaveLength(64);
    expect(wallet.address).toHaveLength(64);
});

test('Near private key derivation from mnemonic', () => {
    const testMnemonic = 'ocean medal extend notice power where require endless shaft tiny dose odor';
    const privateKey = getPrivateKeyByMnemonic(testMnemonic, "m/44'/397'/0'");

    expect(privateKey).toHaveLength(64);
});

test('Near address generation from private key', () => {
    const testPrivateKey = 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807';
    const address = getAddressByPrivateKey(testPrivateKey);

    expect(address).toBeTruthy();
    expect(address).toHaveLength(64);
});

test('Near address equals public key hex', () => {
    const wallet = createWallet({length: 128});
    // Near implicit address is the public key in hex
    expect(wallet.address).toBe(wallet.publicKey);
});

test('Invalid mnemonic throws error', () => {
    expect(() => {
        getPrivateKeyByMnemonic('invalid mnemonic', "m/44'/397'/0'");
    }).toThrow('Invalid mnemonic');
});

test('Invalid private key length throws error', () => {
    expect(() => {
        getAddressByPrivateKey('invalid');
    }).toThrow('Private key must be 64 hex characters (32 bytes)');
});
