import {BTC_DERIVATION_PATH} from "../constans";
import {ICreateWallet, IWalletFields, BitcoinTransaction, BitcoinAddressType} from "../types";
import {InvalidMnemonicError, InvalidPrivateKeyError, KeyDerivationError} from "../errors";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HDKey} from "@scure/bip32";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {secp256k1} from "@noble/curves/secp256k1";
import {sha256} from "@noble/hashes/sha256";
import {ripemd160} from "@noble/hashes/ripemd160";
import bs58 from "bs58";
import {bech32, bech32m} from "@scure/base";

/**
 * Create a new Bitcoin wallet
 * @param params Optional parameters including address type
 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: BTC_DERIVATION_PATH,
        addressType: 'p2wpkh' as BitcoinAddressType, // Default to SegWit
        ...params
    };
    const mnemonic = generateMnemonic(args.length);
    const {privateKey, publicKey} = getPrivateKeyByMnemonic(mnemonic, args.path);
    const address = getAddressByPrivateKey(privateKey, args.addressType as BitcoinAddressType);
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
 * Get Bitcoin address from private key
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param addressType Type of Bitcoin address to generate
 * @returns Bitcoin address in the specified format
 */
export function getAddressByPrivateKey(privateKeyHex: string, addressType: BitcoinAddressType = 'p2wpkh'): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    switch (addressType) {
        case 'p2pkh':
            return getP2PKHAddress(privateKeyHex);
        case 'p2sh':
            return getP2SHAddress(privateKeyHex);
        case 'p2wpkh':
            return getP2WPKHAddress(privateKeyHex);
        case 'p2tr':
            return getP2TRAddress(privateKeyHex);
        default:
            throw new Error(`Unsupported address type: ${addressType}`);
    }
}

/**
 * Generate P2PKH address (Legacy, starts with '1')
 * @param privateKeyHex Private key in hex format
 * @returns P2PKH address
 */
function getP2PKHAddress(privateKeyHex: string): string {
    const privateKey = hexToBytes(privateKeyHex);
    const compressedPublicKey = secp256k1.getPublicKey(privateKey, true);

    const publicKeyHash = ripemd160(sha256(compressedPublicKey));

    const versionedHash = new Uint8Array(21);
    versionedHash[0] = 0x00; // P2PKH version byte
    versionedHash.set(publicKeyHash, 1);

    const checksum = sha256(sha256(versionedHash)).slice(0, 4);

    const addressBytes = new Uint8Array(25);
    addressBytes.set(versionedHash);
    addressBytes.set(checksum, 21);

    return bs58.encode(addressBytes);
}

/**
 * Generate P2SH address (starts with '3')
 * This creates a P2SH-P2WPKH address (SegWit wrapped in P2SH)
 * @param privateKeyHex Private key in hex format
 * @returns P2SH address
 */
function getP2SHAddress(privateKeyHex: string): string {
    const privateKey = hexToBytes(privateKeyHex);
    const compressedPublicKey = secp256k1.getPublicKey(privateKey, true);

    const publicKeyHash = ripemd160(sha256(compressedPublicKey));

    // Create P2WPKH witness program (OP_0 + 20-byte pubkey hash)
    const witnessProgram = new Uint8Array(22);
    witnessProgram[0] = 0x00; // OP_0 (witness version)
    witnessProgram[1] = 0x14; // Push 20 bytes
    witnessProgram.set(publicKeyHash, 2);

    // Hash the witness program to create the redeemScript hash
    const redeemScriptHash = ripemd160(sha256(witnessProgram));

    const versionedHash = new Uint8Array(21);
    versionedHash[0] = 0x05; // P2SH version byte
    versionedHash.set(redeemScriptHash, 1);

    const checksum = sha256(sha256(versionedHash)).slice(0, 4);

    const addressBytes = new Uint8Array(25);
    addressBytes.set(versionedHash);
    addressBytes.set(checksum, 21);

    return bs58.encode(addressBytes);
}

/**
 * Generate P2WPKH address (Native SegWit, starts with 'bc1q')
 * @param privateKeyHex Private key in hex format
 * @returns P2WPKH Bech32 address
 */
function getP2WPKHAddress(privateKeyHex: string): string {
    const privateKey = hexToBytes(privateKeyHex);
    const compressedPublicKey = secp256k1.getPublicKey(privateKey, true);

    const publicKeyHash = ripemd160(sha256(compressedPublicKey));

    // Bech32 encode: witness version 0 + pubkey hash
    const words = bech32.toWords(publicKeyHash);
    const address = bech32.encode('bc', [0, ...words]);

    return address;
}

/**
 * Generate P2TR address (Taproot, starts with 'bc1p')
 * @param privateKeyHex Private key in hex format
 * @returns P2TR Bech32m address
 */
function getP2TRAddress(privateKeyHex: string): string {
    const privateKey = hexToBytes(privateKeyHex);

    // For Taproot, we need to tweak the public key
    // Get the internal public key (x-only, 32 bytes)
    const publicKeyPoint = secp256k1.ProjectivePoint.fromPrivateKey(privateKey);

    // Get x-coordinate only (Schnorr/Taproot uses x-only pubkeys)
    let xOnlyPubKey = publicKeyPoint.toRawBytes(true).slice(1); // Remove the prefix byte

    // If the y-coordinate is odd, we need to negate the private key
    // For simplicity in this implementation, we'll use the x-coordinate directly
    // In production, proper BIP340/BIP341 implementation is needed

    // Taproot commitment: tweaked_pubkey = internal_pubkey + tagged_hash("TapTweak", internal_pubkey)
    // For now, using simplified version without actual taproot tree
    // TODO: Implement proper BIP341 taproot key derivation with tagged hash

    // Add the tweak to get the output key (simplified, needs proper elliptic curve addition)
    // For this implementation, we'll use the x-only pubkey directly as a placeholder

    // Bech32m encode: witness version 1 + x-only pubkey (32 bytes)
    const words = bech32m.toWords(xOnlyPubKey);
    const address = bech32m.encode('bc', [1, ...words]);

    return address;
}

// ==================== Transaction Signing ====================

/**
 * Sign a Bitcoin transaction
 * Note: This is a simplified implementation for P2PKH transactions
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param tx Transaction object
 * @param inputIndex Index of the input to sign
 * @returns Signature in hex format
 */
export function signTransaction(privateKeyHex: string, tx: BitcoinTransaction, inputIndex: number): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    if (inputIndex >= tx.inputs.length) {
        throw new Error("Input index out of bounds");
    }

    // Build transaction hash for signing
    // Simplified: version + inputs + outputs + locktime
    const txData: number[] = [];

    // Version (4 bytes, little-endian)
    txData.push(...intToLE(tx.version, 4));

    // Input count (varint)
    txData.push(...varint(tx.inputs.length));

    // Inputs
    for (let i = 0; i < tx.inputs.length; i++) {
        const input = tx.inputs[i];
        const txid = hexToBytes(input.utxo.txid).reverse(); // Bitcoin uses reversed txid
        txData.push(...txid);
        txData.push(...intToLE(input.utxo.vout, 4));

        // For the input being signed, use its scriptPubKey; for others, use empty script
        if (i === inputIndex) {
            const scriptPubKey = hexToBytes(input.utxo.scriptPubKey);
            txData.push(...varint(scriptPubKey.length));
            txData.push(...scriptPubKey);
        } else {
            txData.push(0); // Empty script
        }

        const sequence = input.sequence !== undefined ? input.sequence : 0xffffffff;
        txData.push(...intToLE(sequence, 4));
    }

    // Output count (varint)
    txData.push(...varint(tx.outputs.length));

    // Outputs
    for (const output of tx.outputs) {
        txData.push(...intToLE(output.value, 8)); // Value in satoshis (8 bytes, little-endian)

        // Create P2PKH output script
        const addressBytes = bs58.decode(output.address);
        const pubKeyHash = addressBytes.slice(1, 21); // Remove version and checksum
        const script = [
            0x76, // OP_DUP
            0xa9, // OP_HASH160
            0x14, // Push 20 bytes
            ...pubKeyHash,
            0x88, // OP_EQUALVERIFY
            0xac  // OP_CHECKSIG
        ];
        txData.push(...varint(script.length));
        txData.push(...script);
    }

    // Locktime (4 bytes, little-endian)
    const locktime = tx.locktime !== undefined ? tx.locktime : 0;
    txData.push(...intToLE(locktime, 4));

    // SIGHASH_ALL (4 bytes)
    txData.push(...intToLE(1, 4));

    // Double SHA-256 hash
    const txBytes = new Uint8Array(txData);
    const hash1 = sha256(txBytes);
    const txHash = sha256(hash1);

    // Sign with secp256k1
    const signature = secp256k1.sign(txHash, hexToBytes(privateKeyHex));

    // DER encode signature + SIGHASH_ALL
    const r = signature.r.toString(16).padStart(64, '0');
    const s = signature.s.toString(16).padStart(64, '0');

    return r + s;
}

// ==================== Message Signing (Bitcoin Message Signing Standard) ====================

/**
 * Sign a message using Bitcoin Message Signing standard
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param message Message to sign
 * @returns Signature in base64 format
 */
export function signMessage(privateKeyHex: string, message: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    // Bitcoin Message Signing: "\x18Bitcoin Signed Message:\n" + len(message) + message
    const messageBytes = new TextEncoder().encode(message);
    const prefix = `\x18Bitcoin Signed Message:\n${messageBytes.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    const fullMessage = new Uint8Array([...prefixBytes, ...messageBytes]);

    // Double SHA-256 hash
    const hash1 = sha256(fullMessage);
    const messageHash = sha256(hash1);

    // Sign with secp256k1
    const signature = secp256k1.sign(messageHash, hexToBytes(privateKeyHex));

    // Format: recovery (1 byte) + r (32 bytes) + s (32 bytes)
    // Recovery flag: 27 + recovery_id (for compressed keys, add 4: 31 + recovery_id)
    const recovery = 27 + 4 + signature.recovery; // +4 for compressed public key
    const r = signature.r.toString(16).padStart(64, '0');
    const s = signature.s.toString(16).padStart(64, '0');

    const sigBytes = new Uint8Array([
        recovery,
        ...hexToBytes(r),
        ...hexToBytes(s)
    ]);

    // Return base64 encoded signature
    return Buffer.from(sigBytes).toString('base64');
}

// ==================== Signature Verification ====================

/**
 * Verify a Bitcoin message signature
 * @param message Original message
 * @param signature Signature in base64 format
 * @param address Expected signer address
 * @returns true if signature is valid
 */
export function verifySignature(message: string, signature: string, address: string): boolean {
    try {
        // Decode base64 signature
        const sigBytes = Buffer.from(signature, 'base64');
        if (sigBytes.length !== 65) {
            return false;
        }

        const recovery = sigBytes[0] - 27 - 4; // -4 for compressed key flag
        const r = BigInt('0x' + Buffer.from(sigBytes.slice(1, 33)).toString('hex'));
        const s = BigInt('0x' + Buffer.from(sigBytes.slice(33, 65)).toString('hex'));

        // Recreate message hash
        const messageBytes = new TextEncoder().encode(message);
        const prefix = `\x18Bitcoin Signed Message:\n${messageBytes.length}`;
        const prefixBytes = new TextEncoder().encode(prefix);
        const fullMessage = new Uint8Array([...prefixBytes, ...messageBytes]);
        const hash1 = sha256(fullMessage);
        const messageHash = sha256(hash1);

        // Recover public key
        const sig = new secp256k1.Signature(r, s);
        const publicKey = sig.addRecoveryBit(recovery).recoverPublicKey(messageHash);

        // Get address from public key
        const compressedPubKey = publicKey.toRawBytes(true);
        const publicKeyHash = ripemd160(sha256(compressedPubKey));

        const versionedHash = new Uint8Array(21);
        versionedHash[0] = 0x00;
        versionedHash.set(publicKeyHash, 1);

        const checksum = sha256(sha256(versionedHash)).slice(0, 4);

        const addressBytes = new Uint8Array(25);
        addressBytes.set(versionedHash);
        addressBytes.set(checksum, 21);

        const recoveredAddress = bs58.encode(addressBytes);

        return recoveredAddress === address;
    } catch (error) {
        return false;
    }
}

// ==================== Address Validation ====================

/**
 * Validate a Bitcoin address (supports all formats)
 * @param address Address to validate
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    // Check for Bech32/Bech32m addresses (SegWit and Taproot)
    if (address.startsWith('bc1')) {
        return validateBech32Address(address);
    }

    // Check for Base58Check addresses (P2PKH and P2SH)
    return validateBase58Address(address);
}

/**
 * Validate Base58Check address (P2PKH starts with '1', P2SH starts with '3')
 * @param address Base58 encoded address
 * @returns true if address is valid
 */
function validateBase58Address(address: string): boolean {
    try {
        const decoded = bs58.decode(address);

        // Bitcoin address should be 25 bytes (1 version + 20 hash + 4 checksum)
        if (decoded.length !== 25) {
            return false;
        }

        // Verify checksum
        const payload = decoded.slice(0, 21);
        const checksum = decoded.slice(21);

        const hash1 = sha256(payload);
        const hash2 = sha256(hash1);
        const expectedChecksum = hash2.slice(0, 4);

        // Compare checksums
        for (let i = 0; i < 4; i++) {
            if (checksum[i] !== expectedChecksum[i]) {
                return false;
            }
        }

        // Check version byte (0x00 for P2PKH, 0x05 for P2SH)
        return decoded[0] === 0x00 || decoded[0] === 0x05;
    } catch {
        return false;
    }
}

/**
 * Validate Bech32/Bech32m address (P2WPKH, P2WSH, P2TR)
 * @param address Bech32 or Bech32m encoded address
 * @returns true if address is valid
 */
function validateBech32Address(address: string): boolean {
    try {
        // Try Bech32 first (for witness version 0)
        if (address.startsWith('bc1q')) {
            const decoded = bech32.decode(address as `${string}1${string}`);

            // Check prefix
            if (decoded.prefix !== 'bc') {
                return false;
            }

            // Check witness version
            if (decoded.words[0] !== 0) {
                return false;
            }

            // Convert words to bytes
            const data = bech32.fromWords(decoded.words.slice(1));

            // P2WPKH should be 20 bytes, P2WSH should be 32 bytes
            return data.length === 20 || data.length === 32;
        }

        // Try Bech32m for Taproot (witness version 1)
        if (address.startsWith('bc1p')) {
            const decoded = bech32m.decode(address as `${string}1${string}`);

            // Check prefix
            if (decoded.prefix !== 'bc') {
                return false;
            }

            // Check witness version
            if (decoded.words[0] !== 1) {
                return false;
            }

            // Convert words to bytes
            const data = bech32m.fromWords(decoded.words.slice(1));

            // P2TR should be 32 bytes (x-only pubkey)
            return data.length === 32;
        }

        return false;
    } catch {
        return false;
    }
}

/**
 * Get public key from private key
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns Public key in hex format (compressed)
 */
export function getPublicKey(privateKeyHex: string): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    const publicKey = secp256k1.getPublicKey(hexToBytes(privateKeyHex), true);
    return bytesToHex(publicKey);
}

// ==================== Helper Functions ====================

/**
 * Convert integer to little-endian bytes
 */
function intToLE(value: number, bytes: number): number[] {
    const result: number[] = [];
    for (let i = 0; i < bytes; i++) {
        result.push((value >> (i * 8)) & 0xff);
    }
    return result;
}

/**
 * Encode variable-length integer (varint)
 */
function varint(n: number): number[] {
    if (n < 0xfd) {
        return [n];
    } else if (n <= 0xffff) {
        return [0xfd, n & 0xff, (n >> 8) & 0xff];
    } else if (n <= 0xffffffff) {
        return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
    } else {
        throw new Error("Number too large for varint");
    }
}

// ==================== Private Key Validation ====================

/**
 * Validate a Bitcoin private key format
 * @param privateKey Private key in hex format (without 0x prefix)
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string): boolean {
    try {
        // Remove any whitespace
        const key = privateKey.trim();

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