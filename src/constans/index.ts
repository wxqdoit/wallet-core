export const HARDENED_OFFSET = 0x80000000;
export const ED25519_CURVE = 'ed25519 seed';

export const pathRegex = new RegExp("^m(\\/[0-9]+')+$");

export const APTOS_DERIVATION_PATH = "m/44'/637'/0'/0'/0'";
export const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";
export const SOLANA_DERIVATION_PATH = "m/44'/501'/0'/0'";
export const EVM_DERIVATION_PATH = "m/44'/60'/0'/0/0";
export const BTC_DERIVATION_PATH = "m/44'/0'/0'/0/0";
export const FILCOIN_DERIVATION_PATH = "m/44'/461'/0'/0'/0'";
export const TRON_DERIVATION_PATH = "m/44'/195'/0'/0/0";
export const TON_DERIVATION_PATH = "m/44'/607'/0'";
export const NEAR_DERIVATION_PATH = "m/44'/397'/0'";

export const SUI_PRIVATE_KEY_PREFIX = 'suiprivkey';

export const SUI_ADDRESS_LENGTH = 32;

export const SIGNATURE_SCHEME_TO_FLAG: Record<string, number> = {
    ED25519: 0,
    Secp256k1: 1,
    Secp256r1: 2,
} as const;

export const FIL_PROTOCOL_INDICATOR: Record<string, number> = {
    SECP256K1: 1,
    BLS: 3,
} as const;
