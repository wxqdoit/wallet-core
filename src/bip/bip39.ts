import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from 'bip39';

export function createMnemonic(strength:number = 256): string {
    return generateMnemonic(strength);
}

export function validateMnemonicPhrase(mnemonic: string): boolean {
    return validateMnemonic(mnemonic);
}

export function mnemonicToSeed(mnemonic: string): Buffer {
    return mnemonicToSeedSync(mnemonic);
}