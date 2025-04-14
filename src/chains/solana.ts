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
import {derivePath} from "../utils/ed25519-hd.ts";


/**
 * Create a new EVM wallet
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: SOLANA_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, args.path);
    const publicKey = ed25519.getPublicKey(privateKey);
    const address = getAddressByPrivateKey(privateKey);
    const concatPrivateKey = new Uint8Array([...privateKey, ...publicKey]);

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
    const publicKey = ed25519.getPublicKey(privateKey);
    return base58.encode(publicKey);
}

/**
 * Get public key by private key
 * @param mnemonic
 * @param hdPath
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string): Uint8Array<ArrayBufferLike> {
    if (!validateMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic');
    }
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);

    // create master key
    const {key} = derivePath(hdPath, seed);

    return key;

}
