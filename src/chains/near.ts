import {ICreateWallet, IWalletFields} from "../types";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {NEAR_DERIVATION_PATH} from "../constans";
import {InvalidMnemonicError, InvalidPrivateKeyError} from "../errors";
import {ed25519} from "@noble/curves/ed25519";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {derivePath} from "../utils/ed25519-hd";

/**
 * Create a new Near wallet
 * Near uses Ed25519 curve
 * Implicit address is the hex-encoded public key (64 characters)
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: NEAR_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, args.path);
    const address = getAddressByPrivateKey(privateKey);
    const publicKey = bytesToHex(ed25519.getPublicKey(hexToBytes(privateKey)));

    return {
        mnemonic,
        privateKey,
        publicKey,
        address
    }
}

/**
 * Get private key from mnemonic
 * @param mnemonic Mnemonic phrase
 * @param hdPath Hierarchical deterministic derivation path
 * @returns Private key in hex format
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string): string {
    if (!validateMnemonic(mnemonic)) {
        throw new InvalidMnemonicError();
    }
    const seed = mnemonicToSeedSync(mnemonic);
    const {key} = derivePath(hdPath, seed);
    return bytesToHex(key);
}

/**
 * Get Near address from private key
 * Near implicit address is the hex-encoded public key
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns NEAR implicit address (hex-encoded public key)
 */
export function getAddressByPrivateKey(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }
    const privateKey = hexToBytes(privateKeyHex);
    const publicKey = ed25519.getPublicKey(privateKey);
    return bytesToHex(publicKey);
}

// ==================== Transaction Signing ====================

/**
 * Sign a NEAR transaction
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

    return bytesToHex(signature);
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
    return bytesToHex(signature);
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
 * Validate a NEAR address
 * NEAR addresses can be:
 * 1. Implicit address: 64 hex characters (32 bytes public key)
 * 2. Named account: alphanumeric with dots and hyphens (e.g., alice.near, bob.testnet)
 * @param address Address to validate
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        // Check if it's an implicit address (64 hex characters)
        if (/^[0-9a-f]{64}$/i.test(address)) {
            return true;
        }

        // Check if it's a named account
        // Named accounts must be 2-64 characters, alphanumeric with dots, hyphens, and underscores
        // Must not start or end with a separator
        if (address.length < 2 || address.length > 64) {
            return false;
        }

        // Named account pattern: lowercase alphanumeric, dots, hyphens, underscores
        // Cannot start/end with separator, no consecutive separators
        // Must contain at least one dot (e.g., .near, .testnet) for proper named accounts
        const namedAccountPattern = /^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$/;
        return namedAccountPattern.test(address);
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
 * Validate a NEAR private key format
 * @param privateKey Private key in hex format (without 0x prefix)
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string): boolean {
    try {
        const key = privateKey.trim();

        // Check length (must be 64 hex chars = 32 bytes)
        if (key.length !== 64) {
            return false;
        }

        // Check if valid hex
        if (!/^[0-9a-f]{64}$/i.test(key)) {
            return false;
        }

        // For ed25519, any 32-byte value is valid
        return true;
    } catch {
        return false;
    }
}
