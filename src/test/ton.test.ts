import {createWallet, getPrivateKeyByMnemonic, getAddressByPrivateKey, getRawAddress} from "../chains/ton";

test('TON wallet creation', () => {
    const wallet = createWallet({length: 128});
    console.log(wallet);

    expect(wallet.mnemonic).toBeTruthy();
    expect(wallet.privateKey).toHaveLength(64);
    expect(wallet.publicKey).toHaveLength(64);
    expect(wallet.address).toBeTruthy();
    // TON user-friendly address is base64url encoded, ~48 chars
    expect(wallet.address.length).toBeGreaterThanOrEqual(40);
});

test('TON private key derivation from mnemonic', () => {
    const testMnemonic = 'ocean medal extend notice power where require endless shaft tiny dose odor';
    const privateKey = getPrivateKeyByMnemonic(testMnemonic, "m/44'/607'/0'");

    expect(privateKey).toHaveLength(64);
});

test('TON address generation from private key', () => {
    const testPrivateKey = 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807';
    const address = getAddressByPrivateKey(testPrivateKey);

    expect(address).toBeTruthy();
    // Base64url encoded address
    expect(address.length).toBeGreaterThanOrEqual(40);
});

test('TON raw address format', () => {
    const testPrivateKey = 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807';
    const rawAddress = getRawAddress(testPrivateKey);

    expect(rawAddress).toBeTruthy();
    // Raw format: workchain:hash
    expect(rawAddress.startsWith('0:')).toBe(true);
    // Hash is 64 hex chars
    expect(rawAddress.length).toBe(66);
});

test('TON deterministic address generation', () => {
    const testPrivateKey = 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807';
    const address1 = getAddressByPrivateKey(testPrivateKey);
    const address2 = getAddressByPrivateKey(testPrivateKey);

    expect(address1).toBe(address2);
});

test('Invalid mnemonic throws error', () => {
    expect(() => {
        getPrivateKeyByMnemonic('invalid mnemonic', "m/44'/607'/0'");
    }).toThrow('Invalid mnemonic');
});

test('Invalid private key length throws error', () => {
    expect(() => {
        getAddressByPrivateKey('invalid');
    }).toThrow('Private key must be 64 hex characters (32 bytes)');
});
