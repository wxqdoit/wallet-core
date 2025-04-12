export const HARDENED_OFFSET = 0x80000000;

export const APTOS_DERIVATION_PATH = "m/44'/637'/0'/0'/0'";
export const SOLANA_DERIVATION_PATH = "m/44'/501'/0'/0'";
export const EVM_DERIVATION_PATH = "m/44'/60'/0'/0/0"

export enum SigningScheme {
    Ed25519 = 0,
    MultiEd25519 = 1,
    SingleKey = 2,
    MultiKey = 3
}