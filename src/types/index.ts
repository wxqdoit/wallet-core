export interface IWalletFields {
    mnemonic: string;
    privateKey: string;
    publicKey?: string;
    address: string;
}
export interface ICreateWallet extends {} {
    length?: 128 | 256,
    path?: string
}