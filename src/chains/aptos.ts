import {bytesToHex} from "@noble/hashes/utils";
import {sha3_256} from '@noble/hashes/sha3';
import {ed25519} from '@noble/curves/ed25519';
import {sha512} from "@noble/hashes/sha512";
import {hmac} from "@noble/hashes/hmac";

import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {APTOS_DERIVATION_PATH, HARDENED_OFFSET, PATH_REGEX, SigningScheme} from "../constans";
import {ICreateWallet, IWalletFeilds} from "../types";




export interface IKeys  {
    key: Uint8Array<ArrayBufferLike>,
    chainCode: Uint8Array<ArrayBufferLike>
}

/**
 * Create a new Aptos wallet
 * @param length
 * @param path
 */
export function createWallet({length = 128, path = APTOS_DERIVATION_PATH}: ICreateWallet):IWalletFeilds {
    const mnemonic = generateMnemonic(length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, path);
    const publicKey = bytesToHex(ed25519.getPublicKey(privateKey))
    const address = getAddressByPrivateKey(privateKey);
    return {
        mnemonic,
        privateKey,
        publicKey,
        address
    }
}


/**
 * Generate master key
 * @param seed
 */
function deriveEd25519MasterKey(seed: Uint8Array): {
    key: Uint8Array;
    code: Uint8Array;
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
    key: Uint8Array,
    chainCode: Uint8Array,
    path: string
): { privateKey: Uint8Array; chainCode: Uint8Array } {

    let _key = key;
    let _chainCode = chainCode;

    const segments = path
    .split('/')
    .slice(1)
    .map(segment => segment.replace("'", ""))
    .map(Number);

    for (const segment of segments) {
        const index = segment + (segment >= HARDENED_OFFSET ? 0 : HARDENED_OFFSET);
        const data = new Uint8Array([
            ...new Uint8Array([0]),
            ..._key,
            ...new Uint8Array([index >> 24, index >> 16, index >> 8, index & 0xff])
        ]);
        const I = hmac(sha512, _chainCode, data)
        _key = I.slice(0, 32);
        _chainCode = I.slice(32);
    }
    return {privateKey: _key, chainCode: _chainCode};
}


/**
 * Get address by private key
 * @param privateKey
 */
export function getAddressByPrivateKey(privateKey: string): string {
    const publicKey = ed25519.getPublicKey(privateKey)
    const hashInput = new Uint8Array([...publicKey, SigningScheme.Ed25519]);
    const hash = sha3_256.create();
    const hashDigest = hash.update(hashInput).digest();
    return bytesToHex(hashDigest);
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
    if (!PATH_REGEX.test(hdPath)) {
        throw new Error('Invalid hdPath');
    }
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);
    // create master key
    const {key, code} = deriveEd25519MasterKey(seed);
    const {privateKey} = derivePath(key, code, hdPath);
    return bytesToHex(privateKey);
}
