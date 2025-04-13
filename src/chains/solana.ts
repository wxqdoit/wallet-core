import {ICreateWallet, IWalletFields} from "../types";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HARDENED_OFFSET, SOLANA_DERIVATION_PATH} from "../constans";
import {HDKey} from "@scure/bip32";
import {base58} from "@scure/base";
import {sha512} from "@noble/hashes/sha512";
import {hmac} from "@noble/hashes/hmac";
import {ed25519} from "@noble/curves/ed25519";
import {bytesToHex} from "@noble/hashes/utils";
import bs58 from 'bs58'


/**
 * Create a new EVM wallet
 * @param length
 * @param path
 */
export function createWallet({length = 128, path}: ICreateWallet): IWalletFields {
    const mnemonic = generateMnemonic(length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, path || SOLANA_DERIVATION_PATH);
    const publicKey = ed25519.getPublicKey(privateKey)
    const address = getAddressByPrivateKey(privateKey);
    const concatPrivateKey = new Uint8Array([...privateKey,...publicKey]);


    return {
        mnemonic,
        privateKey: base58.encode(concatPrivateKey),
        address
    }
}

/**
 * Get address by private key
 * @param privateKey
 */
export function getAddressByPrivateKey(privateKey: Uint8Array<ArrayBufferLike>): string {
    const publicKey = ed25519.getPublicKey(privateKey)
    return base58.encode(publicKey);
}

/**
 * Get public key by private key
 * @param mnemonic
 * @param hdPath
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string) {
    if (!validateMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic');
    }
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);
    // create master key
    const {key, code} = deriveEd25519MasterKey(seed);
    const {privateKey,chainCode} = derivePath(key, code, hdPath);

    return privateKey

}


/**
 * Generate master key
 * @param seed
 */
function deriveEd25519MasterKey(seed: Buffer): {
    key: Uint8Array<ArrayBuffer>;
    code: Uint8Array<ArrayBuffer>;
} {
    // Use HMAC-SHA512 to derive the master key
    const I = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed)
    // Split I into two 32-byte values
    // The first 32 bytes is the private key
    // The second 32 bytes is the chain code
    return {
        key: I.slice(0, 32),
        code: I.slice(32)
    };
}

/**
 * Derive a child key from a parent key using the BIP32 derivation path
 * @param key
 * @param chainCode
 * @param path
 */
function derivePath(
    key: Uint8Array<ArrayBuffer>,
    chainCode: Uint8Array<ArrayBuffer>,
    path: string
): { privateKey: Uint8Array<ArrayBuffer>; chainCode: Uint8Array<ArrayBuffer> } {

    const segments = path
        .split('/')
        .slice(1)
        .map(segment => {
            const isHardened = segment.endsWith("'");
            const index = parseInt(isHardened ? segment.slice(0, -1) : segment, 10);
            return index + (isHardened ? HARDENED_OFFSET : 0);
        });


    for (const index of segments) {
        ({key, chainCode} = deriveChildKey(key, chainCode, index));
    }

    return {privateKey: key, chainCode: chainCode};
}


// 硬化派生子密钥 (索引 >= 0x80000000)
const deriveChildKey = (
    key: Uint8Array<ArrayBuffer>,
    chainCode: Uint8Array<ArrayBuffer>,
    index: number
) => {
    const indexBuffer = new Uint8Array(4);
    new DataView(indexBuffer.buffer).setUint32(0, index, false);

    const data = new Uint8Array([
        0x00, // 硬化标识
        ...key,
        ...indexBuffer
    ]);

    const digest = hmac(sha512, chainCode, data);

    return {
        key: digest.slice(0, 32),
        chainCode: digest.slice(32)
    };
};