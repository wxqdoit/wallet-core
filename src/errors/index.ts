/**
 * Base error class for all wallet-core errors
 */
export class WalletCoreError extends Error {
    constructor(message: string, public code: string) {
        super(message);
        this.name = 'WalletCoreError';
        Object.setPrototypeOf(this, WalletCoreError.prototype);
    }
}

/**
 * Error thrown when mnemonic validation fails
 */
export class InvalidMnemonicError extends WalletCoreError {
    constructor(message: string = 'Invalid mnemonic phrase') {
        super(message, 'INVALID_MNEMONIC');
        this.name = 'InvalidMnemonicError';
    }
}

/**
 * Error thrown when private key is invalid
 */
export class InvalidPrivateKeyError extends WalletCoreError {
    constructor(message: string = 'Invalid private key') {
        super(message, 'INVALID_PRIVATE_KEY');
        this.name = 'InvalidPrivateKeyError';
    }
}

/**
 * Error thrown when key derivation fails
 */
export class KeyDerivationError extends WalletCoreError {
    constructor(message: string = 'Key derivation failed') {
        super(message, 'KEY_DERIVATION_ERROR');
        this.name = 'KeyDerivationError';
    }
}

/**
 * Error thrown when address generation fails
 */
export class AddressGenerationError extends WalletCoreError {
    constructor(message: string = 'Address generation failed') {
        super(message, 'ADDRESS_GENERATION_ERROR');
        this.name = 'AddressGenerationError';
    }
}

/**
 * Error thrown when private key encoding/decoding fails
 */
export class PrivateKeyEncodingError extends WalletCoreError {
    constructor(message: string = 'Private key encoding/decoding failed') {
        super(message, 'PRIVATE_KEY_ENCODING_ERROR');
        this.name = 'PrivateKeyEncodingError';
    }
}

/**
 * Error thrown when invalid parameters are provided
 */
export class InvalidParameterError extends WalletCoreError {
    constructor(message: string = 'Invalid parameter') {
        super(message, 'INVALID_PARAMETER');
        this.name = 'InvalidParameterError';
    }
}
