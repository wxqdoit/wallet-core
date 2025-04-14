import {bytesToHex} from "@noble/hashes/utils";
import {sha3_256} from '@noble/hashes/sha3';
import {ed25519} from '@noble/curves/ed25519';

import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {APTOS_DERIVATION_PATH, SIGNATURE_SCHEME_TO_FLAG, SOLANA_DERIVATION_PATH} from "../constans";
import {ICreateWallet, IWalletFields} from "../types";
import {derivePath} from "../utils/ed25519-hd.ts";


/**
 * Create a new wallet
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: APTOS_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, args.path);
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
    const {key} = derivePath(hdPath, seed);

    return bytesToHex(key);
}
