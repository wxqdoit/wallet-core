import { base58check } from '@scure/base';
import { bech32 } from 'bech32';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { BIP32Interface } from 'bip32';
import { deriveFromSeed } from '../bip/bip32';
import {secp256k1} from "@noble/curves/secp256k1";

export function createWallet(seed: Buffer, path: string = "m/44'/0'/0'/0/0"): string {
    const node = deriveFromSeed(seed).derivePath(path);
    return getAddressByPrivateKey(node.privateKey!.toString('hex'), 'bech32');
}

export function getAddressByPrivateKey(privateKey: string, type: 'p2pkh' | 'p2sh' | 'bech32'): string {
    const publicKey = secp256k1.getPublicKey(privateKey, false);
    const sha = sha256(publicKey);
    const hash = ripemd160(sha);

    switch (type) {
        case 'p2pkh':
            return base58check(sha256).encode(Buffer.concat([Buffer.from([0x00]), hash]));
        case 'p2sh':
            const scriptHash = ripemd160(sha256(Buffer.from(`0014${hash.toString('hex')}`, 'hex')));
            return base58check(sha256).encode(Buffer.concat([Buffer.from([0x05]), scriptHash]));
        case 'bech32':
            return bech32.encode('bc', [0x00, ...bech32.toWords(hash)]);
    }
}