export interface IWalletFeilds {
    mnemonic: string;
    privateKey: string;
    publicKey?: string;
    address: string;
}
export interface ICreateWallet {
    length?: 128 | 256,
    path?: string
}