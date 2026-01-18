/**
 * Persistent test wallet configuration for testnet integration tests
 *
 * IMPORTANT: This mnemonic is for TESTNET ONLY. Never use on mainnet!
 */

export const TEST_MNEMONIC = 'steak treat wait fog two seven pluck sting wife motor machine topic image humor tobacco noodle seven mail staff century swim mimic now february';

/**
 * Test wallet addresses for all supported chains
 * Generated from the test mnemonic above
 */
export const TEST_ADDRESSES = {
    EVM: '0xf741e62a73faa39fab126545e78c20789b0efe3e',
    BTC: 'bc1q6uj9uflfhrej2hlerkrws8d69xxjcssy50gzqs',
    SOLANA: 'GJ7TtwSH8UAcxgFj5jfbpz27gbPtxyLLxvqVUUikT4UJ',
    APTOS: '0xa643ec826a43f4e5ce45e985c017ef0a5559d67aea4525d5320f839a5ad1fbdb',
    SUI: '0xf18c5e78fe1477ecd7994355614947d6940d0720a19265f5da981f85e9aa0043',
    TRON: 'TS2xgUr4gVg25gciBMbwYm2yQa9nusgJX5',
    TON: 'EQCzeTi8pTUYR_34GKyYyjioAXlFMMjfjKFW9BMbdRFvHzwA',
    NEAR: 'cdf9c010ee9b7702944c81ac88df979efcb7cf3e70e7f082c7047a004ddcdb7f',
    FILECOIN: 'f1njwnndkxrwsvlpeyzr4a5s4asrwjsd3rde6573q',
};

/**
 * Faucet URLs for each testnet
 */
export const FAUCET_URLS = {
    // EVM-compatible testnets
    SEPOLIA: 'https://sepoliafaucet.com/',
    SEPOLIA_ALCHEMY: 'https://www.alchemy.com/faucets/ethereum-sepolia',
    POLYGON_MUMBAI: 'https://faucet.polygon.technology/',
    BSC_TESTNET: 'https://testnet.bnbchain.org/faucet-smart',

    // Bitcoin testnet
    BTC_TESTNET: 'https://testnet-faucet.mempool.co/',
    BTC_TESTNET_ALT: 'https://bitcoinfaucet.uo1.net/',

    // Solana
    SOLANA_DEVNET: 'https://faucet.solana.com/',
    SOLANA_CLI: 'solana airdrop 2 <address> --url devnet',

    // Aptos
    APTOS_DEVNET: 'https://aptoslabs.com/testnet-faucet',
    APTOS_CLI: 'aptos account fund-with-faucet --account <address> --network devnet',

    // Sui
    SUI_DEVNET: 'https://discord.gg/sui (use #devnet-faucet channel)',
    SUI_CLI: 'sui client faucet --address <address>',

    // TRON
    TRON_NILE: 'https://nileex.io/join/getJoinPage',
    TRON_SHASTA: 'https://www.trongrid.io/shasta/',

    // TON
    TON_TESTNET: 'https://t.me/testgiver_ton_bot',
    TON_TESTNET_WEB: 'https://ton.org/testnet',

    // NEAR
    NEAR_TESTNET: 'https://near-faucet.io/',
    NEAR_WALLET: 'https://testnet.mynearwallet.com/ (create account gets 200 NEAR)',

    // Filecoin
    FILECOIN_CALIBRATION: 'https://faucet.calibration.fildev.network/',
};

/**
 * Testnet RPC endpoints
 */
export const TESTNET_RPCS = {
    SEPOLIA: 'https://rpc.sepolia.org',
    POLYGON_MUMBAI: 'https://rpc-mumbai.maticvigil.com',
    BSC_TESTNET: 'https://data-seed-prebsc-1-s1.bnbchain.org:8545',
    BTC_TESTNET: 'https://blockstream.info/testnet/api',
    SOLANA_DEVNET: 'https://api.devnet.solana.com',
    APTOS_DEVNET: 'https://fullnode.devnet.aptoslabs.com/v1',
    SUI_DEVNET: 'https://fullnode.devnet.sui.io:443',
    TRON_NILE: 'https://nile.trongrid.io',
    TON_TESTNET: 'https://testnet.toncenter.com/api/v2/jsonRPC',
    NEAR_TESTNET: 'https://rpc.testnet.near.org',
    FILECOIN_CALIBRATION: 'https://api.calibration.node.glif.io/rpc/v1',
};
