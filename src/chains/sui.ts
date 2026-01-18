import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {ed25519} from '@noble/curves/ed25519';
import {blake2b} from '@noble/hashes/blake2b';
import {bech32} from '@scure/base';
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {
    SIGNATURE_SCHEME_TO_FLAG,
    SUI_ADDRESS_LENGTH,
    SUI_DERIVATION_PATH,
    SUI_PRIVATE_KEY_PREFIX
} from "../constans";
import {ICreateWallet, IWalletFields} from "../types";
import {InvalidMnemonicError, InvalidPrivateKeyError} from "../errors";
import {derivePath} from "../utils/ed25519-hd";

/**
 * Create a Sui wallet
 * Sui uses Ed25519 curve with Bech32-encoded private keys
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: SUI_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, args.path);
    const publicKey = bytesToHex(ed25519.getPublicKey(privateKey))
    const address = getAddressByPrivateKey(privateKey);
    return {
        mnemonic,
        privateKey: encodeSuiPrivateKey(hexToBytes(privateKey)),
        publicKey,
        address
    }
}

/**
 * Get Sui address from private key
 * Address = BLAKE2b(0x00 | public_key)[0..32]
 * @param privateKey Private key in hex format or Uint8Array
 * @returns Sui address (0x-prefixed hex string)
 */
export function getAddressByPrivateKey(privateKey: string | Uint8Array): string {
    const publicKey = typeof privateKey === 'string'
        ? ed25519.getPublicKey(hexToBytes(privateKey))
        : ed25519.getPublicKey(privateKey);

    const suiBytes = new Uint8Array(publicKey.length + 1);
    suiBytes.set([SIGNATURE_SCHEME_TO_FLAG.ED25519]);
    suiBytes.set(publicKey, 1);
    return '0x' + bytesToHex(blake2b(suiBytes, {dkLen: 32})).slice(0, SUI_ADDRESS_LENGTH * 2);
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
 * Decode a Sui private key from Bech32 format
 * This returns a parsed keypair object by validating the
 * 33-byte Bech32 encoded string starting with `suiprivkey`, and
 * parse out the signature scheme and the private key in bytes.
 * @param value Bech32-encoded private key (suiprivkey...)
 * @returns Object containing schema and secret key
 */
export function decodeSuiPrivateKey(value: string) {
    const {prefix, words} = bech32.decode(value as `${string}1${string}`);
    if (prefix !== SUI_PRIVATE_KEY_PREFIX) {
        throw new Error('invalid private key prefix');
    }
    const extendedSecretKey = new Uint8Array(bech32.fromWords(words));
    const secretKey = extendedSecretKey.slice(1);
    return {
        schema: extendedSecretKey,
        secretKey: secretKey,
    };
}

/**
 * Encode a Sui private key to Bech32 format
 * This returns a Bech32 encoded string starting with `suiprivkey`,
 * encoding 33-byte `flag || bytes` for the given the 32-byte private
 * key and its signature scheme.
 * @param bytes Private key bytes (32 bytes)
 * @returns Bech32-encoded private key (suiprivkey...)
 */
export function encodeSuiPrivateKey(bytes: Uint8Array<ArrayBufferLike>): string {
    if (bytes.length !== 32) {
        throw new InvalidPrivateKeyError('Private key must be 32 bytes');
    }
    const flag = SIGNATURE_SCHEME_TO_FLAG.ED25519;
    const privKeyBytes = new Uint8Array(bytes.length + 1);
    privKeyBytes.set([flag]);
    privKeyBytes.set(bytes, 1);

    return bech32.encode(SUI_PRIVATE_KEY_PREFIX, bech32.toWords(privKeyBytes)) as string;
}

// ==================== Transaction Signing ====================

/**
 * Sign a Sui transaction
 * @param privateKey Private key in Bech32 format (suiprivkey...) or hex format
 * @param messageBytes Transaction message bytes to sign
 * @returns Signature in hex format
 */
export function signTransaction(privateKey: string, messageBytes: Uint8Array): string {
    let secretKey: Uint8Array;

    // Check if it's a Bech32-encoded private key
    if (privateKey.startsWith(SUI_PRIVATE_KEY_PREFIX)) {
        const decoded = decodeSuiPrivateKey(privateKey);
        secretKey = decoded.secretKey;
    } else {
        // Assume it's hex format
        if (privateKey.length !== 64) {
            throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
        }
        secretKey = hexToBytes(privateKey);
    }

    const signature = ed25519.sign(messageBytes, secretKey);
    return bytesToHex(signature);
}

// ==================== Message Signing ====================

/**
 * Sign a message using Ed25519
 * @param privateKey Private key in Bech32 format (suiprivkey...) or hex format
 * @param message Message to sign (string or Uint8Array)
 * @returns Signature in hex format
 */
export function signMessage(privateKey: string, message: string | Uint8Array): string {
    let secretKey: Uint8Array;

    // Check if it's a Bech32-encoded private key
    if (privateKey.startsWith(SUI_PRIVATE_KEY_PREFIX)) {
        const decoded = decodeSuiPrivateKey(privateKey);
        secretKey = decoded.secretKey;
    } else {
        // Assume it's hex format
        if (privateKey.length !== 64) {
            throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
        }
        secretKey = hexToBytes(privateKey);
    }

    // Convert message to bytes
    const messageBytes = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;

    const signature = ed25519.sign(messageBytes, secretKey);
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
 * Validate a Sui address
 * Sui address is 0x-prefixed hex string of 64 characters (32 bytes)
 * @param address Address to validate (with or without 0x prefix)
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        // Remove 0x prefix if present
        const addr = address.toLowerCase().replace('0x', '');

        // Check length (32 bytes = 64 hex characters)
        if (addr.length !== SUI_ADDRESS_LENGTH * 2) {
            return false;
        }

        // Check if it's valid hex
        if (!/^[0-9a-f]{64}$/.test(addr)) {
            return false;
        }

        return true;
    } catch {
        return false;
    }
}

/**
 * Get public key from private key
 * @param privateKey Private key in Bech32 format (suiprivkey...) or hex format
 * @returns Public key in hex format
 */
export function getPublicKey(privateKey: string): string {
    let secretKey: Uint8Array;

    // Check if it's a Bech32-encoded private key
    if (privateKey.startsWith(SUI_PRIVATE_KEY_PREFIX)) {
        const decoded = decodeSuiPrivateKey(privateKey);
        secretKey = decoded.secretKey;
    } else {
        // Assume it's hex format
        if (privateKey.length !== 64) {
            throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
        }
        secretKey = hexToBytes(privateKey);
    }

    const publicKey = ed25519.getPublicKey(secretKey);
    return bytesToHex(publicKey);
}

// ==================== Private Key Validation ====================

/**
 * Validate a Sui private key format
 * Accepts both Bech32 (suiprivkey...) and hex formats
 * @param privateKey Private key in Bech32 or hex format
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string): boolean {
    try {
        const key = privateKey.trim();

        // Check if it's a Bech32-encoded private key (suiprivkey...)
        if (key.startsWith('suiprivkey')) {
            try {
                const decoded = decodeSuiPrivateKey(key);
                // Should have 32-byte secret key
                return decoded.secretKey.length === 32;
            } catch {
                return false;
            }
        }

        // Check hex format
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
