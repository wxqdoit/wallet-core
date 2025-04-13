import {EVM_DERIVATION_PATH} from "../constans";
import {ICreateWallet,  IWalletFields} from "../types";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HDKey} from "@scure/bip32";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak_256} from "@noble/hashes/sha3";

/**
 * Create a new EVM wallet
 * @param length
 * @param path
 */
export function createWallet({length = 128, path }: ICreateWallet): IWalletFields {
    const mnemonic = generateMnemonic(length);
    const {privateKey, publicKey} = getPrivateKeyByMnemonic(mnemonic, path || EVM_DERIVATION_PATH);
    const address = getAddressByPrivateKey(privateKey);
    return {
        mnemonic,
        privateKey,
        publicKey,
        address
    }
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
    const masterKey = HDKey.fromMasterSeed(seed);

    const key = masterKey.derive(hdPath);

    if(!key.publicKey || !key.privateKey) {
        throw new Error('Invalid key');
    }

    return {
        privateKey: bytesToHex(key.privateKey),
        publicKey: bytesToHex(key.publicKey),
    }

}

/**
 * Get address by private key
 * @param privateKeyHex
 */
export function getAddressByPrivateKey(privateKeyHex: string): string {

    if (privateKeyHex.length !== 64) {
        throw new Error("Invalid private key length");
    }
    const privateKey = hexToBytes(privateKeyHex);

    const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);

    const pubKeyRaw = uncompressedPublicKey.slice(1);

    const hash = keccak_256(pubKeyRaw);

    return bytesToHex(hash.slice(-20));
}