import { ed25519 } from '@noble/curves/ed25519';
import { sha3_256 } from '@noble/hashes/sha3';
import { base58 } from '@scure/base';
import fromSeed from "bip32";

interface SolanaWallet {
    privateKey: string;
    publicKey: string;
    address: string;
}

const SOLANA_DERIVATION_PATH = "m/44'/501'/0'/0'";

export function createWallet(seed: Buffer, path: string = SOLANA_DERIVATION_PATH): SolanaWallet {
    const privateKey = derivePrivateKey(seed, path);
    const publicKey = ed25519.getPublicKey(privateKey);
    return {
        privateKey: base58.encode(privateKey),
        publicKey: base58.encode(publicKey),
        address: getAddressByPublicKey(publicKey)
    };
}

function derivePrivateKey(seed: Buffer, path: string): Uint8Array {
    // 使用 BIP32-Ed25519 规范实现派生
    const node = fromSeed(seed).derivePath(path);
    return node.privateKey!;
}

export function getAddressByPrivateKey(privateKey: string): string {
    const pubKey = ed25519.getPublicKey(base58.decode(privateKey));
    return getAddressByPublicKey(pubKey);
}

function getAddressByPublicKey(publicKey: Uint8Array): string {
    const hashed = sha3_256(publicKey);
    return base58.encode(hashed);
}

// 关键安全处理
const secureBuffer = (bytes: Uint8Array): Uint8Array => {
    // 使用 WebAssembly 隔离内存
    const wasmMem = new WebAssembly.Memory({ initial: 1 });
    const view = new Uint8Array(wasmMem.buffer);
    view.set(bytes);
    return view.slice(0, 64);
};