import {TRON_DERIVATION_PATH} from "../constans";
import {ICreateWallet, IWalletFields} from "../types";
import {InvalidMnemonicError, InvalidPrivateKeyError, KeyDerivationError} from "../errors";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HDKey} from "@scure/bip32";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak_256} from "@noble/hashes/sha3";
import {sha256} from "@noble/hashes/sha256";
import bs58 from "bs58";

/**
 * Create a new Tron wallet
 * TRON uses secp256k1 curve (like Ethereum) but with different address format
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: TRON_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const {privateKey, publicKey} = getPrivateKeyByMnemonic(mnemonic, args.path);
    const address = getAddressByPrivateKey(privateKey);
    return {
        mnemonic,
        privateKey,
        publicKey,
        address
    }
}

/**
 * Get private key and public key from mnemonic
 * @param mnemonic Mnemonic phrase
 * @param hdPath Hierarchical deterministic derivation path
 * @returns Private key and public key in hex format
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string) {
    if (!validateMnemonic(mnemonic)) {
        throw new InvalidMnemonicError();
    }
    const seed = mnemonicToSeedSync(mnemonic);
    const masterKey = HDKey.fromMasterSeed(seed);
    const key = masterKey.derive(hdPath);

    if (!key.publicKey || !key.privateKey) {
        throw new KeyDerivationError('Failed to derive key from path');
    }

    return {
        privateKey: bytesToHex(key.privateKey),
        publicKey: bytesToHex(key.publicKey),
    }
}

/**
 * Get Tron address from private key
 * Tron address format: Base58Check with 0x41 prefix, starts with 'T'
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns TRON address starting with 'T'
 */
export function getAddressByPrivateKey(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }
    const privateKey = hexToBytes(privateKeyHex);

    // Get uncompressed public key (65 bytes, starts with 0x04)
    const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);

    // Remove the 0x04 prefix
    const pubKeyRaw = uncompressedPublicKey.slice(1);

    // Keccak-256 hash
    const hash = keccak_256(pubKeyRaw);

    // Take last 20 bytes
    const addressBytes = hash.slice(-20);

    // Add Tron version prefix 0x41
    const versionedAddress = new Uint8Array(21);
    versionedAddress[0] = 0x41;
    versionedAddress.set(addressBytes, 1);

    // Double SHA-256 for checksum
    const firstHash = sha256(versionedAddress);
    const secondHash = sha256(firstHash);
    const checksum = secondHash.slice(0, 4);

    // Combine versioned address and checksum
    const addressWithChecksum = new Uint8Array(25);
    addressWithChecksum.set(versionedAddress);
    addressWithChecksum.set(checksum, 21);

    // Base58 encode
    return bs58.encode(addressWithChecksum);
}

// ==================== Transaction Signing ====================

/**
 * Sign a TRON transaction
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param txHash Transaction hash to sign (32 bytes)
 * @returns Signature in hex format
 */
export function signTransaction(privateKeyHex: string, txHash: Uint8Array): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);
    const signature = secp256k1.sign(txHash, privateKey);

    // Format: r (32 bytes) + s (32 bytes) + v (1 byte)
    const r = signature.r.toString(16).padStart(64, '0');
    const s = signature.s.toString(16).padStart(64, '0');
    const v = signature.recovery.toString(16).padStart(2, '0');

    return r + s + v;
}

// ==================== Message Signing ====================

/**
 * Sign a message using TRON's message signing standard
 * TRON uses the same format as Ethereum (EIP-191)
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param message Message to sign
 * @returns Signature in hex format
 */
export function signMessage(privateKeyHex: string, message: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    // Convert message to bytes
    let messageBytes: Uint8Array;
    if (message.startsWith('0x')) {
        messageBytes = hexToBytes(message.slice(2));
    } else {
        messageBytes = new TextEncoder().encode(message);
    }

    // TRON uses same format as Ethereum: "\x19TRON Signed Message:\n" + len(message) + message
    const prefix = `\x19TRON Signed Message:\n${messageBytes.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    const fullMessage = new Uint8Array([...prefixBytes, ...messageBytes]);

    const messageHash = keccak_256(fullMessage);
    const signature = secp256k1.sign(messageHash, hexToBytes(privateKeyHex));

    // Format: r (32 bytes) + s (32 bytes) + v (1 byte)
    const v = signature.recovery + 27;
    return signature.r.toString(16).padStart(64, '0') +
        signature.s.toString(16).padStart(64, '0') +
        v.toString(16).padStart(2, '0');
}

// ==================== Signature Verification ====================

/**
 * Verify a TRON message signature
 * @param message Original message
 * @param signature Signature in hex format (130 characters: r + s + v)
 * @param expectedAddress Expected signer address (TRON address starting with T)
 * @returns true if signature is valid
 */
export function verifySignature(message: string, signature: string, expectedAddress: string): boolean {
    try {
        // Remove 0x prefix if present
        const sig = signature.startsWith('0x') ? signature.slice(2) : signature;
        if (sig.length !== 130) { // 65 bytes * 2
            return false;
        }

        const r = sig.slice(0, 64);
        const s = sig.slice(64, 128);
        const v = parseInt(sig.slice(128, 130), 16);

        // Convert message to bytes
        let messageBytes: Uint8Array;
        if (message.startsWith('0x')) {
            messageBytes = hexToBytes(message.slice(2));
        } else {
            messageBytes = new TextEncoder().encode(message);
        }

        // TRON message format
        const prefix = `\x19TRON Signed Message:\n${messageBytes.length}`;
        const prefixBytes = new TextEncoder().encode(prefix);
        const fullMessage = new Uint8Array([...prefixBytes, ...messageBytes]);
        const messageHash = keccak_256(fullMessage);

        // Recover public key from signature
        const recovery = v - 27;
        const sig2 = new secp256k1.Signature(BigInt('0x' + r), BigInt('0x' + s));
        const publicKey = sig2.addRecoveryBit(recovery).recoverPublicKey(messageHash);

        // Get address from public key
        const uncompressedPubKey = publicKey.toRawBytes(false);
        const pubKeyRaw = uncompressedPubKey.slice(1);
        const hash = keccak_256(pubKeyRaw);
        const addressBytes = hash.slice(-20);

        // Add Tron version prefix
        const versionedAddress = new Uint8Array(21);
        versionedAddress[0] = 0x41;
        versionedAddress.set(addressBytes, 1);

        // Add checksum
        const firstHash = sha256(versionedAddress);
        const secondHash = sha256(firstHash);
        const checksum = secondHash.slice(0, 4);

        const addressWithChecksum = new Uint8Array(25);
        addressWithChecksum.set(versionedAddress);
        addressWithChecksum.set(checksum, 21);

        const recoveredAddress = bs58.encode(addressWithChecksum);

        return recoveredAddress === expectedAddress;
    } catch (error) {
        return false;
    }
}

// ==================== Address Validation ====================

/**
 * Validate a TRON address
 * TRON address is Base58Check encoded with 0x41 prefix (starts with 'T')
 * @param address Address to validate
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        // TRON addresses should start with 'T'
        if (!address.startsWith('T')) {
            return false;
        }

        const decoded = bs58.decode(address);

        // TRON address should be 25 bytes (1 version + 20 address + 4 checksum)
        if (decoded.length !== 25) {
            return false;
        }

        // Verify version byte (0x41 for TRON mainnet)
        if (decoded[0] !== 0x41) {
            return false;
        }

        // Verify checksum
        const payload = decoded.slice(0, 21);
        const checksum = decoded.slice(21);

        const firstHash = sha256(payload);
        const secondHash = sha256(firstHash);
        const expectedChecksum = secondHash.slice(0, 4);

        // Compare checksums
        for (let i = 0; i < 4; i++) {
            if (checksum[i] !== expectedChecksum[i]) {
                return false;
            }
        }

        return true;
    } catch {
        return false;
    }
}

/**
 * Get public key from private key
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns Public key in hex format (uncompressed)
 */
export function getPublicKey(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const publicKey = secp256k1.getPublicKey(hexToBytes(privateKeyHex), true);
    return bytesToHex(publicKey);
}

// ==================== Private Key Validation ====================

/**
 * Validate a TRON private key format
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

        // Convert to BigInt and check range
        // secp256k1 curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        const keyBigInt = BigInt('0x' + key);
        const secp256k1_n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

        // Private key must be: 0 < key < n
        if (keyBigInt === BigInt(0) || keyBigInt >= secp256k1_n) {
            return false;
        }

        return true;
    } catch {
        return false;
    }
}
