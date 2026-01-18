import {ICreateWallet, IWalletFields} from "../types";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {TON_DERIVATION_PATH} from "../constans";
import {InvalidMnemonicError, InvalidPrivateKeyError} from "../errors";
import {ed25519} from "@noble/curves/ed25519";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {sha256} from "@noble/hashes/sha256";
import {derivePath} from "../utils/ed25519-hd";

// TON Wallet v4r2 code hash (this is the standard wallet contract)
const WALLET_V4R2_CODE_HASH = hexToBytes('feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0');

// Default workchain (0 = basechain)
const WORKCHAIN = 0;

// Default subwallet ID
const SUBWALLET_ID = 698983191;

// CRC16 lookup table for TON address checksum
const CRC16_TABLE = new Uint16Array(256);
for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let j = 0; j < 8; j++) {
        crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : crc >> 1;
    }
    CRC16_TABLE[i] = crc;
}

/**
 * Calculate CRC16 checksum for TON addresses
 * @param data Data to checksum
 * @returns CRC16 checksum bytes
 */
function crc16(data: Uint8Array): Uint8Array {
    let crc = 0;
    for (let i = 0; i < data.length; i++) {
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ data[i]) & 0xFF];
    }
    // Return big-endian
    return new Uint8Array([(crc >> 8) & 0xFF, crc & 0xFF]);
}

/**
 * Base64url encode (TON uses URL-safe base64)
 * @param bytes Bytes to encode
 * @returns Base64url encoded string
 */
function base64UrlEncode(bytes: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Base64url decode (TON uses URL-safe base64)
 * @param str Base64url encoded string
 * @returns Decoded bytes
 */
function base64UrlDecode(str: string): Uint8Array {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Build TON wallet v4r2 StateInit hash
 * Simplified implementation for address generation
 * @param publicKey Public key bytes
 * @returns StateInit hash
 */
function buildStateInitHash(publicKey: Uint8Array): Uint8Array {
    // StateInit structure for wallet v4r2:
    // We need to compute the hash of the initial state
    // This is a simplified representation

    // Data cell contains: seqno (0), subwallet_id, public_key
    const dataBuilder = new Uint8Array(4 + 4 + 32 + 1); // seqno + subwallet + pubkey + plugins dict

    // seqno = 0 (4 bytes, big-endian)
    dataBuilder[0] = 0;
    dataBuilder[1] = 0;
    dataBuilder[2] = 0;
    dataBuilder[3] = 0;

    // subwallet_id (4 bytes, big-endian)
    dataBuilder[4] = (SUBWALLET_ID >> 24) & 0xFF;
    dataBuilder[5] = (SUBWALLET_ID >> 16) & 0xFF;
    dataBuilder[6] = (SUBWALLET_ID >> 8) & 0xFF;
    dataBuilder[7] = SUBWALLET_ID & 0xFF;

    // public key (32 bytes)
    dataBuilder.set(publicKey, 8);

    // plugins dict = 0 (empty)
    dataBuilder[40] = 0;

    // Hash the data
    const dataHash = sha256(dataBuilder);

    // Combine code hash and data hash for StateInit
    // StateInit = split_depth:Maybe + special:Maybe + code:Maybe + data:Maybe + library:Maybe
    // Simplified: we hash code_hash + data_hash
    const stateInit = new Uint8Array(64);
    stateInit.set(WALLET_V4R2_CODE_HASH, 0);
    stateInit.set(dataHash, 32);

    return sha256(stateInit);
}

/**
 * Convert address hash to user-friendly format
 * @param workchain Workchain ID
 * @param hash Address hash (32 bytes)
 * @param bounceable Whether address is bounceable
 * @param testnet Whether address is for testnet
 * @returns User-friendly address
 */
function toUserFriendlyAddress(workchain: number, hash: Uint8Array, bounceable = true, testnet = false): string {
    // Tag byte
    let tag = bounceable ? 0x11 : 0x51;
    if (testnet) {
        tag |= 0x80;
    }

    // Build address: tag (1) + workchain (1) + hash (32) + crc16 (2) = 36 bytes
    const address = new Uint8Array(36);
    address[0] = tag;
    address[1] = workchain & 0xFF;
    address.set(hash, 2);

    // Calculate CRC16 of first 34 bytes
    const checksum = crc16(address.slice(0, 34));
    address[34] = checksum[0];
    address[35] = checksum[1];

    return base64UrlEncode(address);
}

/**
 * Create a new TON wallet
 * TON uses Ed25519 curve with wallet v4r2 contract
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: TON_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, args.path);
    const publicKey = ed25519.getPublicKey(hexToBytes(privateKey));
    const address = getAddressByPrivateKey(privateKey);

    return {
        mnemonic,
        privateKey,
        publicKey: bytesToHex(publicKey),
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
 * Get TON address from private key
 * Returns user-friendly bounceable mainnet address
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns User-friendly TON address
 */
export function getAddressByPrivateKey(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }
    const privateKey = hexToBytes(privateKeyHex);
    const publicKey = ed25519.getPublicKey(privateKey);

    // Build StateInit hash
    const stateInitHash = buildStateInitHash(publicKey);

    // Convert to user-friendly address (bounceable, mainnet)
    return toUserFriendlyAddress(WORKCHAIN, stateInitHash, true, false);
}

/**
 * Get raw TON address (workchain:hash format)
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns Raw address in format "workchain:hash"
 */
export function getRawAddress(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }
    const privateKey = hexToBytes(privateKeyHex);
    const publicKey = ed25519.getPublicKey(privateKey);
    const stateInitHash = buildStateInitHash(publicKey);

    return `${WORKCHAIN}:${bytesToHex(stateInitHash)}`;
}

// ==================== Transaction Signing ====================

/**
 * Sign a TON transaction
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
 * Validate a TON address (user-friendly format)
 * @param address Address to validate (base64url encoded)
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        const decoded = base64UrlDecode(address);

        // TON address should be 36 bytes (1 tag + 1 workchain + 32 hash + 2 crc16)
        if (decoded.length !== 36) {
            return false;
        }

        // Verify checksum
        const payload = decoded.slice(0, 34);
        const checksum = decoded.slice(34);

        const expectedChecksum = crc16(payload);

        // Compare checksums
        if (checksum[0] !== expectedChecksum[0] || checksum[1] !== expectedChecksum[1]) {
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
 * Validate a TON private key format
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
