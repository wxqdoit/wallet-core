import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {ed25519} from '@noble/curves/ed25519';
import {blake2b} from '@noble/hashes/blake2b';
import { bech32 } from '@scure/base';
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {SIGNATURE_SCHEME_TO_FLAG, SUI_ADDRESS_LENGTH, SUI_DERIVATION_PATH, SUI_PRIVATE_KEY_PREFIX} from "../constans";
import {ICreateWallet, IWalletFields} from "../types";
import {derivePath} from "../utils/ed25519-hd.ts";


/**
 * create wallet
 * @param length
 * @param path
 * @param algo
 */
export function createWallet({length, path}: ICreateWallet): IWalletFields {
    const mnemonic = generateMnemonic(length || 128);

    const privateKey = getPrivateKeyByMnemonic(mnemonic, path || SUI_DERIVATION_PATH);
    const publicKey = bytesToHex(ed25519.getPublicKey(privateKey))
    const address = getAddressByPrivateKey(privateKey);
    return {
        mnemonic,
        privateKey:encodeSuiPrivateKey(hexToBytes(privateKey)),
        publicKey,
        address
    }
}


/**
 * Get address by private key
 * @param privateKey
 */
export function getAddressByPrivateKey(privateKey: string): string {
    const publicKey = ed25519.getPublicKey(privateKey)
    const suiBytes = new Uint8Array(publicKey.length + 1);
    suiBytes.set([SIGNATURE_SCHEME_TO_FLAG.ED25519]);
    suiBytes.set(publicKey, 1);
    return bytesToHex(blake2b(suiBytes, {dkLen: 32})).slice(0, SUI_ADDRESS_LENGTH * 2)
}

/**
 * Get public key by private key
 * @param mnemonic
 * @param hdPath
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string): string {
    if (!validateMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic');
    }
    const seed = mnemonicToSeedSync(mnemonic);
    const {key, chainCode} = derivePath(hdPath, seed);
    return bytesToHex(key);
}



/**
 * This returns an ParsedKeypair object based by validating the
 * 33-byte Bech32 encoded string starting with `suiprivkey`, and
 * parse out the signature scheme and the private key in bytes.
 */
export function decodeSuiPrivateKey(value: string) {
    const { prefix, words } = bech32.decode(value as `${string}1${string}`);
    if (prefix !== SUI_PRIVATE_KEY_PREFIX) {
        throw new Error('invalid private key prefix');
    }
    const extendedSecretKey = new Uint8Array(bech32.fromWords(words));
    const secretKey = extendedSecretKey.slice(1);
    return {
        schema: extendedSecretKey,
        secretKey: secretKey,
    };
}

/**
 * This returns a Bech32 encoded string starting with `suiprivkey`,
 * encoding 33-byte `flag || bytes` for the given the 32-byte private
 * key and its signature scheme.
 */
export function encodeSuiPrivateKey(bytes: Uint8Array<ArrayBufferLike>): string {
    if (bytes.length !== 32) {
        throw new Error('Invalid bytes length');
    }
    const flag = SIGNATURE_SCHEME_TO_FLAG.ED25519;
    const privKeyBytes = new Uint8Array(bytes.length + 1);
    privKeyBytes.set([flag]);
    privKeyBytes.set(bytes, 1);

    return bech32.encode(SUI_PRIVATE_KEY_PREFIX, bech32.toWords(privKeyBytes)) as string

}
