import {ICreateWallet, IWalletFields} from "../types";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {SOLANA_DERIVATION_PATH} from "../constans";
import {base58} from "@scure/base";
import {ed25519} from "@noble/curves/ed25519";
import {derivePath} from "../utils/ed25519-hd";
import {InvalidMnemonicError, InvalidPrivateKeyError} from "../errors";

/**
 * Create a new Solana wallet
 * @param params
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: SOLANA_DERIVATION_PATH,
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const privateKey = getPrivateKeyByMnemonic(mnemonic, args.path);
    const publicKey = ed25519.getPublicKey(privateKey);
    const address = getAddressByPrivateKey(privateKey);
    const concatPrivateKey = new Uint8Array([...privateKey, ...publicKey]);

    return {
        mnemonic,
        privateKey: base58.encode(concatPrivateKey),
        publicKey: base58.encode(publicKey),
        address
    }
}

/**
 * Get address by private key
 * @param privateKey
 */
export function getAddressByPrivateKey(privateKey: Uint8Array<ArrayBufferLike>): string {
    const publicKey = ed25519.getPublicKey(privateKey);
    return base58.encode(publicKey);
}

/**
 * Get public key by private key
 * @param mnemonic
 * @param hdPath
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string): Uint8Array<ArrayBufferLike> {
    if (!validateMnemonic(mnemonic)) {
        throw new InvalidMnemonicError();
    }
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);

    // create master key
    const {key} = derivePath(hdPath, seed);

    return key;
}

// ==================== Transaction Signing ====================

/**
 * Sign a Solana transaction
 * @param privateKeyBase58 Private key in base58 format (64 bytes with public key appended)
 * @param messageBytes Transaction message bytes
 * @returns Signature in base58 format
 */
export function signTransaction(privateKeyBase58: string, messageBytes: Uint8Array): string {
    try {
        // Decode private key (first 32 bytes are the secret key)
        const fullKey = base58.decode(privateKeyBase58);
        if (fullKey.length !== 64) {
            throw new InvalidPrivateKeyError("Solana private key must be 64 bytes");
        }

        const secretKey = fullKey.slice(0, 32);
        const signature = ed25519.sign(messageBytes, secretKey);

        return base58.encode(signature);
    } catch (error) {
        throw new Error(`Failed to sign transaction: ${error}`);
    }
}

/**
 * Sign a message
 * @param privateKeyBase58 Private key in base58 format
 * @param message Message to sign (string or Uint8Array)
 * @returns Signature in base58 format
 */
export function signMessage(privateKeyBase58: string, message: string | Uint8Array): string {
    try {
        // Decode private key
        const fullKey = base58.decode(privateKeyBase58);
        if (fullKey.length !== 64) {
            throw new InvalidPrivateKeyError("Solana private key must be 64 bytes");
        }

        const secretKey = fullKey.slice(0, 32);

        // Convert message to bytes
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        const signature = ed25519.sign(messageBytes, secretKey);
        return base58.encode(signature);
    } catch (error) {
        throw new Error(`Failed to sign message: ${error}`);
    }
}

// ==================== Signature Verification ====================

/**
 * Verify a signature
 * @param message Original message
 * @param signature Signature in base58 format
 * @param publicKey Public key in base58 format
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

        const signatureBytes = base58.decode(signature);
        const publicKeyBytes = base58.decode(publicKey);

        return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } catch (error) {
        return false;
    }
}

// ==================== Address Validation ====================

/**
 * Validate a Solana address (base58 encoded public key)
 * @param address Address to validate
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    try {
        const decoded = base58.decode(address);
        // Solana public keys are 32 bytes
        return decoded.length === 32;
    } catch {
        return false;
    }
}

/**
 * Get public key from private key
 * @param privateKeyBase58 Private key in base58 format
 * @returns Public key in base58 format
 */
export function getPublicKey(privateKeyBase58: string): string {
    try {
        const fullKey = base58.decode(privateKeyBase58);
        if (fullKey.length !== 64) {
            throw new InvalidPrivateKeyError("Solana private key must be 64 bytes");
        }

        // Public key is the last 32 bytes
        const publicKey = fullKey.slice(32);
        return base58.encode(publicKey);
    } catch (error) {
        throw new Error(`Failed to get public key: ${error}`);
    }
}

// ==================== Private Key Validation ====================

/**
 * Validate a Solana private key format
 * Accepts either base58 encoded (64 bytes) or hex format (64 chars)
 * @param privateKey Private key in base58 or hex format
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string): boolean {
    try {
        // Remove any whitespace
        const key = privateKey.trim();

        // Try base58 format first (Solana standard)
        if (!/^[0-9a-f]{64}$/i.test(key)) {
            try {
                const decoded = base58.decode(key);
                // Solana private key should be 64 bytes (32 bytes secret + 32 bytes public)
                return decoded.length === 64;
            } catch {
                return false;
            }
        }

        // Hex format (32 bytes = 64 hex chars)
        if (key.length !== 64) {
            return false;
        }

        // Check if valid hex
        if (!/^[0-9a-f]{64}$/i.test(key)) {
            return false;
        }

        // For ed25519, any 32-byte value is valid (no range check needed like secp256k1)
        return true;
    } catch {
        return false;
    }
}
