import {EVM_DERIVATION_PATH, PATH_REGEX} from "../constans";
import {ICreateWallet, IWalletFeilds} from "../types";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HDKey} from "@scure/bip32";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak_256} from "@noble/hashes/sha3";

/**
 * Create a new Aptos wallet
 * @param length
 * @param path
 */
export function createWallet({length = 128, path = EVM_DERIVATION_PATH}: ICreateWallet): IWalletFeilds {
    const mnemonic = generateMnemonic(length);
    const {privateKey, publicKey} = getPrivateKeyByMnemonic(mnemonic, path);
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
    if (!PATH_REGEX.test(hdPath)) {
        throw new Error('Invalid hdPath');
    }
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);
    // create master key
    const masterKey = HDKey.fromMasterSeed(seed);
    // 派生指定路径的子密钥
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
// 1. 标准化私钥格式（移除0x前缀，确保64字符）
    const cleanPrivateKeyHex = privateKeyHex.startsWith("0x")
        ? privateKeyHex.slice(2)
        : privateKeyHex;
    if (cleanPrivateKeyHex.length !== 64) {
        throw new Error("Invalid private key length");
    }
    // 2. 将私钥转换为 Uint8Array
    const privateKey = hexToBytes(cleanPrivateKeyHex);

    // 3. 推导非压缩公钥（65字节，前缀0x04）
    const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);

    // 5. 从非压缩公钥生成 EVM 地址
    // 移除非压缩公钥前缀（0x04）
    const pubKeyRaw = uncompressedPublicKey.slice(1);
    // 计算 Keccak-256 哈希
    const hash = keccak_256(pubKeyRaw);
    // 取后20字节并添加0x前缀
    return bytesToHex(hash.slice(-20));
}