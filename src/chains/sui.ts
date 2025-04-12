import { blake2b } from '@noble/hashes/blake2b';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import { toHEX } from '@mysten/bcs';

const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";

interface SuiWallet {
    keyPair: {
        publicKey: string;
        privateKey: string;
    };
    address: string;
}

export function createWallet(seed: Buffer, path: string = SUI_DERIVATION_PATH): SuiWallet {
    const privateKey = derivePrivateKey(seed, path);
    const publicKey = ed25519.getPublicKey(privateKey);

    // SUI 地址生成规范
    const publicKeyBytes = new Uint8Array(publicKey);
    const addressData = new Uint8Array(publicKeyBytes.length + 1);
    addressData.set([0x00]); // ED25519 flag
    addressData.set(publicKeyBytes, 1);
    const address = base58.encode(blake2b(addressData, { dkLen: 32 }));

    return {
        keyPair: {
            publicKey: toHEX(publicKey),
            privateKey: toHEX(privateKey)
        },
        address: `0x${address}`
    };
}

function derivePrivateKey(seed: Buffer, path: string): Uint8Array {
    // 使用 BIP32 派生后截断
    const node = fromSeed(seed).derivePath(path);
    return node.privateKey!.slice(0, 32);
}

export function getAddressFromPublicKey(publicKey: Uint8Array): string {
    const addressData = new Uint8Array(publicKey.length + 1);
    addressData.set([0x00]);
    addressData.set(publicKey, 1);
    return `0x${base58.encode(blake2b(addressData, { dkLen: 32 }))}`;
}