import {bytesToHex} from "@noble/hashes/utils";
import {sha3_256} from '@noble/hashes/sha3';
import {ed25519} from '@noble/curves/ed25519';

import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {APTOS_DERIVATION_PATH, SIGNATURE_SCHEME_TO_FLAG} from "../constans";
import {ICreateWallet, IWalletFields} from "../types";
import {derivePath} from "../utils/ed25519-hd.ts";


/**
 * Create a new wallet
 * @param length
 * @param path
 */
export function createWallet({length = 128, path}: ICreateWallet):IWalletFields {
    const mnemonic =  generateMnemonic(length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, path ||  APTOS_DERIVATION_PATH);
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
 * Get address by private key
 * @param privateKey
 */
export function getAddressByPrivateKey(privateKey: string): string {
    const publicKey = ed25519.getPublicKey(privateKey)
    const hashInput = new Uint8Array([...publicKey, SIGNATURE_SCHEME_TO_FLAG.ED25519]);
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
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);
    // create master key
    const {privateKey} = derivePath(hdPath,seed);

    return bytesToHex(privateKey);
}
