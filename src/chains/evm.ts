import {EVM_DERIVATION_PATH} from "../constans";
import {ICreateWallet, IWalletFields, EVMTransaction} from "../types";
import {InvalidMnemonicError, InvalidPrivateKeyError, KeyDerivationError, AddressGenerationError} from "../errors";
import {generateMnemonic, mnemonicToSeedSync, validateMnemonic} from "bip39";
import {HDKey} from "@scure/bip32";
import {bytesToHex, hexToBytes} from "@noble/hashes/utils";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak_256} from "@noble/hashes/sha3";

/**
 * Create a new EVM wallet
 * @param params

 */
export function createWallet(params?: ICreateWallet): IWalletFields {
    const args = {
        length: 128,
        path: EVM_DERIVATION_PATH,
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
 * Get public key by private key
 * @param mnemonic
 * @param hdPath
 */
export function getPrivateKeyByMnemonic(mnemonic: string, hdPath: string) {
    if (!validateMnemonic(mnemonic)) {
        throw new InvalidMnemonicError();
    }
    // mnemonic to seed
    const seed = mnemonicToSeedSync(mnemonic);
    // create master key
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
 * Get address by private key
 * @param privateKeyHex
 */
export function getAddressByPrivateKey(privateKeyHex: string): string {

    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }
    const privateKey = hexToBytes(privateKeyHex);

    const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);

    const pubKeyRaw = uncompressedPublicKey.slice(1);

    const hash = keccak_256(pubKeyRaw);

    return bytesToHex(hash.slice(-20));
}

// ==================== RLP Encoding ====================

/**
 * RLP encode a value
 */
function encodeLength(length: number, offset: number): number[] {
    if (length < 56) {
        return [length + offset];
    }
    const hexLength = length.toString(16);
    const lengthLength = hexLength.length / 2;
    const firstByte = offset + 55 + lengthLength;
    return [firstByte, ...hexToBytes(hexLength.padStart(lengthLength * 2, '0'))];
}

function rlpEncode(input: any): Uint8Array {
    if (Array.isArray(input)) {
        const output: number[] = [];
        for (const item of input) {
            output.push(...rlpEncode(item));
        }
        return new Uint8Array([...encodeLength(output.length, 0xc0), ...output]);
    }

    // Convert to bytes
    let bytes: Uint8Array;
    if (typeof input === 'string') {
        if (input.startsWith('0x')) {
            const hex = input.slice(2);
            // Pad hex string if it has odd length
            const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex;
            bytes = paddedHex.length === 0 ? new Uint8Array(0) : hexToBytes(paddedHex);
        } else {
            bytes = new TextEncoder().encode(input);
        }
    } else if (typeof input === 'number') {
        if (input === 0) {
            bytes = new Uint8Array(0);
        } else {
            bytes = hexToBytes(input.toString(16).padStart(input.toString(16).length % 2 ? input.toString(16).length + 1 : input.toString(16).length, '0'));
        }
    } else {
        bytes = input;
    }

    if (bytes.length === 1 && bytes[0] < 0x80) {
        return bytes;
    }

    return new Uint8Array([...encodeLength(bytes.length, 0x80), ...bytes]);
}

// ==================== Transaction Signing ====================

/**
 * Sign an EVM transaction
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param tx Transaction object
 * @returns Signed transaction as hex string (with 0x prefix)
 */
export function signTransaction(privateKeyHex: string, tx: EVMTransaction): string {
    if (privateKeyHex.length !== 64) {
        throw new InvalidPrivateKeyError("Private key must be 64 hex characters (32 bytes)");
    }

    // Legacy transaction (Type 0)
    if (!tx.type || tx.type === 0) {
        const txArray = [
            '0x' + tx.nonce.toString(16),
            tx.gasPrice || '0x0',
            tx.gasLimit,
            tx.to,
            tx.value,
            tx.data || '0x',
            '0x' + tx.chainId.toString(16),
            '0x',
            '0x'
        ];

        const rlpEncoded = rlpEncode(txArray);
        const txHash = keccak_256(rlpEncoded);

        const signature = secp256k1.sign(txHash, hexToBytes(privateKeyHex));
        const v = Number(signature.recovery) + 35 + tx.chainId * 2;

        const signedTxArray = [
            '0x' + tx.nonce.toString(16),
            tx.gasPrice || '0x0',
            tx.gasLimit,
            tx.to,
            tx.value,
            tx.data || '0x',
            '0x' + v.toString(16),
            '0x' + signature.r.toString(16).padStart(64, '0'),
            '0x' + signature.s.toString(16).padStart(64, '0')
        ];

        return '0x' + bytesToHex(rlpEncode(signedTxArray));
    }

    // EIP-1559 transaction (Type 2)
    if (tx.type === 2) {
        const txArray = [
            '0x' + tx.chainId.toString(16),
            '0x' + tx.nonce.toString(16),
            tx.maxPriorityFeePerGas || '0x0',
            tx.maxFeePerGas || '0x0',
            tx.gasLimit,
            tx.to,
            tx.value,
            tx.data || '0x',
            []  // accessList
        ];

        const rlpEncoded = rlpEncode(txArray);
        const txBytes = new Uint8Array([0x02, ...rlpEncoded]);
        const txHash = keccak_256(txBytes);

        const signature = secp256k1.sign(txHash, hexToBytes(privateKeyHex));

        const signedTxArray = [
            '0x' + tx.chainId.toString(16),
            '0x' + tx.nonce.toString(16),
            tx.maxPriorityFeePerGas || '0x0',
            tx.maxFeePerGas || '0x0',
            tx.gasLimit,
            tx.to,
            tx.value,
            tx.data || '0x',
            [],  // accessList
            '0x' + Number(signature.recovery).toString(16),
            '0x' + signature.r.toString(16).padStart(64, '0'),
            '0x' + signature.s.toString(16).padStart(64, '0')
        ];

        return '0x02' + bytesToHex(rlpEncode(signedTxArray));
    }

    throw new Error(`Unsupported transaction type: ${tx.type}`);
}

// ==================== Message Signing (EIP-191) ====================

/**
 * Sign a message using EIP-191 standard (personal_sign)
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @param message Message to sign (string or hex)
 * @returns Signature as hex string (with 0x prefix)
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

    // EIP-191: "\x19Ethereum Signed Message:\n" + len(message) + message
    const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
    const prefixBytes = new TextEncoder().encode(prefix);
    const fullMessage = new Uint8Array([...prefixBytes, ...messageBytes]);

    const messageHash = keccak_256(fullMessage);
    const signature = secp256k1.sign(messageHash, hexToBytes(privateKeyHex));

    // Format: r (32 bytes) + s (32 bytes) + v (1 byte)
    const v = signature.recovery + 27;
    return '0x' +
        signature.r.toString(16).padStart(64, '0') +
        signature.s.toString(16).padStart(64, '0') +
        v.toString(16).padStart(2, '0');
}

// ==================== Signature Verification ====================

/**
 * Verify a message signature
 * @param message Original message
 * @param signature Signature (with 0x prefix)
 * @param expectedAddress Expected signer address (without 0x prefix)
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

        // EIP-191: "\x19Ethereum Signed Message:\n" + len(message) + message
        const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
        const prefixBytes = new TextEncoder().encode(prefix);
        const fullMessage = new Uint8Array([...prefixBytes, ...messageBytes]);
        const messageHash = keccak_256(fullMessage);

        // Recover public key from signature
        const recovery = v - 27;
        const sig2 = new secp256k1.Signature(BigInt('0x' + r), BigInt('0x' + s));
        const publicKey = sig2.addRecoveryBit(recovery).recoverPublicKey(messageHash);

        // Get address from public key
        const uncompressedPubKey = publicKey.toRawBytes(false);
        const pubKeyHash = keccak_256(uncompressedPubKey.slice(1));
        const recoveredAddress = bytesToHex(pubKeyHash.slice(-20));

        // Compare addresses (case-insensitive)
        const expected = expectedAddress.toLowerCase().replace('0x', '');
        return recoveredAddress.toLowerCase() === expected;
    } catch (error) {
        return false;
    }
}

// ==================== Address Validation ====================

/**
 * Validate an EVM address
 * @param address Address to validate (with or without 0x prefix)
 * @returns true if address is valid
 */
export function validateAddress(address: string): boolean {
    // Check for null/undefined
    if (!address) {
        return false;
    }

    // Remove 0x prefix if present
    const addr = address.toLowerCase().replace('0x', '');

    // Check length (20 bytes = 40 hex characters)
    if (addr.length !== 40) {
        return false;
    }

    // Check if it's valid hex
    if (!/^[0-9a-f]{40}$/.test(addr)) {
        return false;
    }

    return true;
}

/**
 * Convert address to EIP-55 checksum format
 * @param address Address (with or without 0x prefix)
 * @returns Checksummed address with 0x prefix
 */
export function toChecksumAddress(address: string): string {
    const addr = address.toLowerCase().replace('0x', '');

    if (!validateAddress(addr)) {
        throw new AddressGenerationError('Invalid address format');
    }

    const hash = bytesToHex(keccak_256(new TextEncoder().encode(addr)));
    let checksumAddr = '0x';

    for (let i = 0; i < addr.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            checksumAddr += addr[i].toUpperCase();
        } else {
            checksumAddr += addr[i];
        }
    }

    return checksumAddr;
}

/**
 * Get public key from private key
 * @param privateKeyHex Private key in hex format (without 0x prefix)
 * @returns Public key in hex format (without 0x prefix)
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
 * Validate a private key format
 * @param privateKey Private key in hex format (with or without 0x prefix)
 * @returns true if private key is valid
 */
export function validatePrivateKey(privateKey: string): boolean {
    try {
        // Remove 0x prefix if present
        const key = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;

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