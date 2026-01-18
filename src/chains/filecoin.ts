import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {blake2b} from '@noble/hashes/blake2b';
import {ed25519} from '@noble/curves/ed25519';
import {secp256k1} from '@noble/curves/secp256k1';
import {base32} from '@scure/base';
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HDKey} from "@scure/bip32";
import {FILCOIN_DERIVATION_PATH, FIL_PROTOCOL_INDICATOR} from "../constans";
import {ICreateWallet, IWalletFields, FilecoinAddressType} from "../types";
import {InvalidMnemonicError, InvalidPrivateKeyError} from "../errors";
import {derivePath} from "../utils/ed25519-hd";

/**
 * Create a new Filecoin wallet
 * Filecoin supports multiple signature schemes (SECP256K1, BLS)
 * @param params Optional parameters including address type
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: FILCOIN_DERIVATION_PATH,
        addressType: 'secp256k1' as FilecoinAddressType, // Default to secp256k1
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const {privateKey, publicKey} = getPrivateKeyByMnemonic(mnemonic, args.path, args.addressType as FilecoinAddressType);
    const address = getAddressByPrivateKey(privateKey, args.addressType as FilecoinAddressType);
    return {
        mnemonic,
        privateKey,
        publicKey,
        address
    }
}

/**
 * Get Filecoin address from private key
 * Filecoin uses a custom address format with protocol indicator and checksum
 * Format: f<protocol><payload><checksum>
 * @param privateKey Private key in hex format or Uint8Array
 * @param addressType Type of address to generate (secp256k1 or bls)
 * @returns Filecoin address (f1... for secp256k1, f3... for bls)
 */
export function getAddressByPrivateKey(
    privateKey: string | Uint8Array,
    addressType: FilecoinAddressType = 'secp256k1'
): string {
    if (addressType === 'secp256k1') {
        return getSecp256k1Address(privateKey);
    } else {
        return getBLSAddress(privateKey);
    }
}

/**
 * Generate secp256k1 address (f1...)
 * @param privateKey Private key in hex format or Uint8Array
 * @returns Filecoin f1 address
 */
function getSecp256k1Address(privateKey: string | Uint8Array): string {
    const publicKey = typeof privateKey === 'string'
        ? secp256k1.getPublicKey(hexToBytes(privateKey), false) // Uncompressed public key
        : secp256k1.getPublicKey(privateKey, false);

    // Protocol 1 = SECP256K1
    const protocol = FIL_PROTOCOL_INDICATOR.SECP256K1;

    // Hash public key with BLAKE2b-160 (20 bytes)
    const hash = blake2b(publicKey, {dkLen: 20});

    // Combine protocol + hash for checksum calculation
    const payload = new Uint8Array([protocol, ...hash]);

    // Calculate checksum (BLAKE2b-32 of the payload, take first 4 bytes)
    const checksum = blake2b(payload, {dkLen: 4});

    // Encode only hash + checksum to base32 (protocol goes separately)
    const addressBytes = new Uint8Array([...hash, ...checksum]);

    // Encode to base32 (lowercase)
    const encoded = base32.encode(addressBytes).toLowerCase();

    // Remove padding
    const unpaddedEncoded = encoded.replace(/=/g, '');

    return 'f' + protocol + unpaddedEncoded;
}

/**
 * Generate BLS address (f3...)
 * Note: This implementation uses Ed25519 as a placeholder for BLS
 * A production implementation should use actual BLS12-381 signatures
 * @param privateKey Private key in hex format or Uint8Array
 * @returns Filecoin f3 address
 */
function getBLSAddress(privateKey: string | Uint8Array): string {
    const publicKey = typeof privateKey === 'string'
        ? ed25519.getPublicKey(hexToBytes(privateKey))
        : ed25519.getPublicKey(privateKey);

    // Protocol 3 = BLS
    const protocol = FIL_PROTOCOL_INDICATOR.BLS;

    // Hash public key with BLAKE2b-160 (20 bytes)
    const hash = blake2b(publicKey, {dkLen: 20});

    // Combine protocol + hash for checksum calculation
    const payload = new Uint8Array([protocol, ...hash]);

    // Calculate checksum (BLAKE2b-32 of the payload, take first 4 bytes)
    const checksum = blake2b(payload, {dkLen: 4});

    // Encode only hash + checksum to base32 (protocol goes separately)
    const addressBytes = new Uint8Array([...hash, ...checksum]);

    // Encode to base32 (lowercase)
    const encoded = base32.encode(addressBytes).toLowerCase();

    // Remove padding
    const unpaddedEncoded = encoded.replace(/=/g, '');

    return 'f' + protocol + unpaddedEncoded;
}

/**
 * Get private key and public key from mnemonic
 * @param mnemonic Mnemonic phrase
 * @param hdPath Hierarchical deterministic derivation path
 * @param addressType Type of address (secp256k1 or bls)
 * @returns Private key and public key in hex format
 */
export function getPrivateKeyByMnemonic(
    mnemonic: string,
    hdPath: string,
    addressType: FilecoinAddressType = 'secp256k1'
): { privateKey: string; publicKey: string } {
    if (!validateMnemonic(mnemonic)) {
        throw new InvalidMnemonicError();
    }
    const seed = mnemonicToSeedSync(mnemonic);

    if (addressType === 'secp256k1') {
        // Use BIP32 for secp256k1
        const masterKey = HDKey.fromMasterSeed(seed);
        const key = masterKey.derive(hdPath);

        if (!key.publicKey || !key.privateKey) {
            throw new Error('Failed to derive key from path');
        }

        return {
            privateKey: bytesToHex(key.privateKey),
            publicKey: bytesToHex(key.publicKey),
        };
    } else {
        // Use Ed25519 HD for BLS (as placeholder)
        const {key} = derivePath(hdPath, seed);
        const publicKey = ed25519.getPublicKey(key);

        return {
            privateKey: bytesToHex(key),
            publicKey: bytesToHex(publicKey),
        };
    }
}

// ==================== Transaction Signing ====================

/**
 * Sign a Filecoin transaction
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param messageBytes Transaction message bytes to sign
 * @param addressType Type of address (secp256k1 or bls)
 * @returns Signature in hex format
 */
export function signTransaction(
    privateKeyHex: string,
    messageBytes: Uint8Array,
    addressType: FilecoinAddressType = 'secp256k1'
): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);

    if (addressType === 'secp256k1') {
        // Use secp256k1 signature
        const signature = secp256k1.sign(messageBytes, privateKey);
        return signature.toCompactHex();
    } else {
        // Use Ed25519 signature (placeholder for BLS)
        const signature = ed25519.sign(messageBytes, privateKey);
        return bytesToHex(signature);
    }
}

// ==================== Message Signing ====================

/**
 * Sign a message
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param message Message to sign (string or Uint8Array)
 * @param addressType Type of address (secp256k1 or bls)
 * @returns Signature in hex format
 */
export function signMessage(
    privateKeyHex: string,
    message: string | Uint8Array,
    addressType: FilecoinAddressType = 'secp256k1'
): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);

    // Convert message to bytes
    const messageBytes = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;

    if (addressType === 'secp256k1') {
        // Use secp256k1 signature
        const signature = secp256k1.sign(messageBytes, privateKey);
        return signature.toCompactHex();
    } else {
        // Use Ed25519 signature (placeholder for BLS)
        const signature = ed25519.sign(messageBytes, privateKey);
        return bytesToHex(signature);
    }
}

// ==================== Signature Verification ====================

/**
 * Verify a signature
 * @param message Original message (string or Uint8Array)
 * @param signature Signature in hex format (with or without 0x prefix)
 * @param publicKey Public key in hex format (with or without 0x prefix)
 * @param addressType Type of address (secp256k1 or bls)
 * @returns true if signature is valid
 */
export function verifySignature(
    message: string | Uint8Array,
    signature: string,
    publicKey: string,
    addressType: FilecoinAddressType = 'secp256k1'
): boolean {
    try {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        const sig = signature.startsWith('0x') ? signature.slice(2) : signature;
        const pub = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;

        if (addressType === 'secp256k1') {
            // Verify secp256k1 signature
            const signatureBytes = hexToBytes(sig);
            const publicKeyBytes = hexToBytes(pub);
            return secp256k1.verify(signatureBytes, messageBytes, publicKeyBytes);
        } else {
            // Verify Ed25519 signature (placeholder for BLS)
            const signatureBytes = hexToBytes(sig);
            const publicKeyBytes = hexToBytes(pub);
            return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
        }
    } catch (error) {
        return false;
    }
}

// ==================== Address Validation ====================

/**
 * Validate a Filecoin address
 * Filecoin addresses start with 'f' or 't' (testnet) followed by protocol indicator
 * @param address Address to validate
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        // Filecoin addresses must start with 'f' (mainnet) or 't' (testnet)
        if (!address.startsWith('f') && !address.startsWith('t')) {
            return false;
        }

        // Remove network prefix
        const payload = address.slice(1);

        // Address must have reasonable length
        if (payload.length < 2 || payload.length > 100) {
            return false;
        }

        // Get protocol indicator (first character after network prefix)
        const protocol = payload[0];

        // Valid protocols: 0 (ID), 1 (SECP256K1), 2 (Actor), 3 (BLS)
        if (!/^[0-3]/.test(protocol)) {
            return false;
        }

        // For protocol 0 (ID addresses), rest should be numeric
        if (protocol === '0') {
            return /^[0-9]+$/.test(payload.slice(1));
        }

        // For other protocols, decode base32 and verify checksum
        const addressData = payload.slice(1);

        // Pad base32 string if needed
        const padded = addressData.toUpperCase() + '='.repeat((8 - (addressData.length % 8)) % 8);

        const decoded = base32.decode(padded);

        // Should have at least payload + checksum (minimum 5 bytes)
        if (decoded.length < 5) {
            return false;
        }

        // Verify checksum
        const payloadBytes = decoded.slice(0, -4);
        const checksum = decoded.slice(-4);

        // Add protocol back to payload
        const fullPayload = new Uint8Array([parseInt(protocol), ...payloadBytes]);
        const expectedChecksum = blake2b(fullPayload, {dkLen: 4});

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
 * @param addressType Type of address (secp256k1 or bls)
 * @returns Public key in hex format
 */
export function getPublicKey(privateKeyHex: string, addressType: FilecoinAddressType = 'secp256k1'): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const privateKey = hexToBytes(privateKeyHex);

    if (addressType === 'secp256k1') {
        const publicKey = secp256k1.getPublicKey(privateKey, true); // Compressed
        return bytesToHex(publicKey);
    } else {
        const publicKey = ed25519.getPublicKey(privateKey);
        return bytesToHex(publicKey);
    }
}

// ==================== Private Key Validation ====================

/**
 * Validate a Filecoin private key format
 * @param privateKey Private key in hex format (without 0x prefix)
 * @param addressType Type of address (secp256k1 or bls) - affects range validation
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string, addressType: FilecoinAddressType = 'secp256k1'): boolean {
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

        // For secp256k1, check range
        if (addressType === 'secp256k1') {
            const keyBigInt = BigInt('0x' + key);
            const secp256k1_n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

            // Private key must be: 0 < key < n
            if (keyBigInt === BigInt(0) || keyBigInt >= secp256k1_n) {
                return false;
            }
        }
        // For BLS (ed25519), any 32-byte value is valid

        return true;
    } catch {
        return false;
    }
}
