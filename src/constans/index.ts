export const HARDENED_OFFSET = 0x80000000;
export const ED25519_CURVE = 'ed25519 seed';

export const pathRegex = new RegExp("^m(\\/[0-9]+')+$");

export const APTOS_DERIVATION_PATH = "m/44'/637'/0'/0'/0'";
export const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";

export const SOLANA_DERIVATION_PATH = "m/44'/501'/0'/0'";
export const EVM_DERIVATION_PATH = "m/44'/60'/0'/0/0"


export const SUI_PRIVATE_KEY_PREFIX = 'suiprivkey';

export const SUI_ADDRESS_LENGTH = 32;

export const SIGNATURE_SCHEME_TO_FLAG = {
    ED25519: 0x00,
    Secp256k1: 0x01,
    Secp256r1: 0x02,
    MultiSig: 0x03,
    ZkLogin: 0x05,
    Passkey: 0x06,
} as const;
