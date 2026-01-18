import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {sha3_256} from '@noble/hashes/sha3';
import {ed25519} from '@noble/curves/ed25519';

import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {APTOS_DERIVATION_PATH, SIGNATURE_SCHEME_TO_FLAG} from "../constans";
import {ICreateWallet, IWalletFields} from "../types";
import {InvalidMnemonicError, InvalidPrivateKeyError} from "../errors";
import {derivePath} from "../utils/ed25519-hd";

/**
 * Create a new Aptos wallet
 * Aptos uses Ed25519 curve
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
 * Get Aptos address from private key
 * Address = SHA3-256(public_key | 0x00) where 0x00 is ED25519 signature scheme flag
 * @param privateKey Private key in hex format or Uint8Array
 * @returns Address in hex format (64 characters)
 */
export function getAddressByPrivateKey(privateKey: string | Uint8Array): string {
    const publicKey = typeof privateKey === 'string'
        ? ed25519.getPublicKey(hexToBytes(privateKey))
        : ed25519.getPublicKey(privateKey);

    const hashInput = new Uint8Array([...publicKey, SIGNATURE_SCHEME_TO_FLAG.ED25519]);
    const hash = sha3_256.create();
    const hashDigest = hash.update(hashInput).digest();
    return '0x' + bytesToHex(hashDigest);
}

/**
 * Get private key from mnemonic
 * @param mnemonic Mnemonic phrase
 * @param hdPath Hierarchical deterministic derivation path
 * @returns Private key in hex format
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string) {
    if (!validateMnemonic(mnemonic)) {
        throw new InvalidMnemonicError();
    }
    const seed = mnemonicToSeedSync(mnemonic);
    const {key} = derivePath(hdPath, seed);

    return bytesToHex(key);
}

// ==================== Transaction Signing ====================

/**
 * Sign an Aptos transaction
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param messageBytes Transaction message bytes to sign
 * @returns Signature in hex format
 */
export function signTransaction(privateKeyHex: string, messageBytes: Uint8Array): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);
    const signature = ed25519.sign(messageBytes, privateKey);

    return '0x' + bytesToHex(signature);
}

// ==================== Message Signing ====================

/**
 * Sign a message using Ed25519
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param message Message to sign (string or Uint8Array)
 * @returns Signature in hex format
 */
export function signMessage(privateKeyHex: string, message: string | Uint8Array): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);

    // Convert message to bytes
    const messageBytes = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;

    const signature = ed25519.sign(messageBytes, privateKey);
    return '0x' + bytesToHex(signature);
}

// ==================== Signature Verification ====================

/**
 * Verify an Ed25519 signature
 * @param message Original message (string or Uint8Array)
 * @param signature Signature in hex format (with or without 0x prefix)
 * @param publicKey Public key in hex format (with or without 0x prefix)
 * @returns true if signature is valid
 */
export function verifySignature(
    message: string | Uint8Array,
    signature: string,
    publicKey: string
): boolean {
    try {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        const sig = signature.startsWith('0x') ? signature.slice(2) : signature;
        const pub = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;

        const signatureBytes = hexToBytes(sig);
        const publicKeyBytes = hexToBytes(pub);

        return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } catch (error) {
        return false;
    }
}

// ==================== Address Validation ====================

/**
 * Validate an Aptos address
 * Aptos address is a 64-character hex string (32 bytes)
 * @param address Address to validate (with or without 0x prefix)
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        // Remove 0x prefix if present
        const addr = address.toLowerCase().replace('0x', '');

        // Aptos allows short addresses (like 0x1) up to 64 hex characters (32 bytes)
        if (addr.length === 0 || addr.length > 64) {
            return false;
        }

        // Check if it's valid hex
        if (!/^[0-9a-f]+$/.test(addr)) {
            return false;
        }

        return true;
    } catch {
        return false;
    }
}

/**
 * Get public key from private key
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns Public key in hex format
 */
export function getPublicKey(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);
    const publicKey = ed25519.getPublicKey(privateKey);
    return bytesToHex(publicKey);
}

// ==================== Private Key Validation ====================

/**
 * Validate an Aptos private key format
 * @param privateKey Private key in hex format (with or without 0x prefix)
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string): boolean {
    try {
        // Remove 0x prefix if present
        const key = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey.trim();

        // Check length (must be 64 hex chars = 32 bytes)
        if (key.length !== 64) {
            return false;
        }

        // Check if valid hex
        if (!/^[0-9a-f]{64}$/i.test(key)) {
            return false;
        }

        // For ed25519, any 32-byte value is valid (no range check needed)
        return true;
    } catch {
        return false;
    }
}
