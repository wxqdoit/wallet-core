/**
 * Generate test addresses - run once to get addresses for testnet-config.ts
 */

import * as EVM from '../chains/evm';
import * as BTC from '../chains/btc';
import * as Solana from '../chains/solana';
import * as Aptos from '../chains/aptos';
import * as Sui from '../chains/sui';
import * as Tron from '../chains/tron';
import * as Ton from '../chains/ton';
import * as Near from '../chains/near';
import * as Filecoin from '../chains/filecoin';

const TEST_MNEMONIC = 'steak treat wait fog two seven pluck sting wife motor machine topic image humor tobacco noodle seven mail staff century swim mimic now february';

describe('Generate Test Addresses', () => {
    test('should generate all test addresses from persistent mnemonic', () => {
        console.log('\n🔑 PERSISTENT TEST WALLET ADDRESSES\n');
        console.log('Mnemonic:', TEST_MNEMONIC);
        console.log('\n⚠️  WARNING: TESTNET ONLY - NEVER USE ON MAINNET!\n');

        // EVM
        const evmKeys = EVM.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/60'/0'/0/0");
        const evmAddress = EVM.getAddressByPrivateKey(evmKeys.privateKey);
        console.log('📗 EVM (Ethereum Sepolia / BSC Testnet / Polygon Mumbai):');
        console.log(`   Address: 0x${evmAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - Sepolia: https://sepoliafaucet.com/`);
        console.log(`   - BSC Testnet: https://testnet.bnbchain.org/faucet-smart`);
        console.log(`   - Polygon Mumbai: https://faucet.polygon.technology/\n`);

        // Bitcoin
        const btcKeys = BTC.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/84'/0'/0'/0/0");
        const btcAddress = BTC.getAddressByPrivateKey(btcKeys.privateKey, 'p2wpkh');
        console.log('🟠 Bitcoin Testnet:');
        console.log(`   Address: ${btcAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - https://testnet-faucet.mempool.co/`);
        console.log(`   - https://bitcoinfaucet.uo1.net/\n`);

        // Solana
        const solanaPrivateKey = Solana.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/501'/0'/0'");
        const solanaAddress = Solana.getAddressByPrivateKey(solanaPrivateKey);
        console.log('🟣 Solana Devnet:');
        console.log(`   Address: ${solanaAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - Web: https://faucet.solana.com/`);
        console.log(`   - CLI: solana airdrop 2 ${solanaAddress} --url devnet\n`);

        // Aptos
        const aptosPrivateKey = Aptos.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/637'/0'/0'/0'");
        const aptosAddress = Aptos.getAddressByPrivateKey(aptosPrivateKey);
        console.log('⚫ Aptos Devnet:');
        console.log(`   Address: ${aptosAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - Web: https://aptoslabs.com/testnet-faucet`);
        console.log(`   - CLI: aptos account fund-with-faucet --account ${aptosAddress}\n`);

        // Sui
        const suiPrivateKey = Sui.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/784'/0'/0'/0'");
        const suiAddress = Sui.getAddressByPrivateKey(suiPrivateKey);
        console.log('🔵 Sui Devnet:');
        console.log(`   Address: ${suiAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - Discord: https://discord.gg/sui (use #devnet-faucet channel)`);
        console.log(`   - CLI: sui client faucet\n`);

        // TRON
        const tronKeys = Tron.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/195'/0'/0/0");
        const tronAddress = Tron.getAddressByPrivateKey(tronKeys.privateKey);
        console.log('🔴 TRON Nile Testnet:');
        console.log(`   Address: ${tronAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - Nile: https://nileex.io/join/getJoinPage`);
        console.log(`   - Shasta: https://www.trongrid.io/shasta/\n`);

        // TON
        const tonPrivateKey = Ton.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/607'/0'/0'/0'");
        const tonAddress = Ton.getAddressByPrivateKey(tonPrivateKey);
        console.log('💎 TON Testnet:');
        console.log(`   Address: ${tonAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - Telegram Bot: https://t.me/testgiver_ton_bot`);
        console.log(`   - Web: https://ton.org/testnet\n`);

        // NEAR
        const nearPrivateKey = Near.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/397'/0'");
        const nearAddress = Near.getAddressByPrivateKey(nearPrivateKey);
        console.log('⚪ NEAR Testnet:');
        console.log(`   Implicit Address: ${nearAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - https://near-faucet.io/`);
        console.log(`   - Create wallet at https://testnet.mynearwallet.com/ (gets 200 NEAR)\n`);

        // Filecoin
        const filecoinKeys = Filecoin.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0/0", 'secp256k1');
        const filecoinAddress = Filecoin.getAddressByPrivateKey(filecoinKeys.privateKey, 'secp256k1');
        console.log('⚡ Filecoin Calibration Testnet:');
        console.log(`   Address: ${filecoinAddress}`);
        console.log(`   Faucets:`);
        console.log(`   - https://faucet.calibration.fildev.network/\n`);

        console.log('═'.repeat(80));
        console.log('\n📋 Copy these addresses to src/test/testnet-config.ts:\n');
        console.log(`export const TEST_ADDRESSES = {`);
        console.log(`    EVM: '0x${evmAddress}',`);
        console.log(`    BTC: '${btcAddress}',`);
        console.log(`    SOLANA: '${solanaAddress}',`);
        console.log(`    APTOS: '${aptosAddress}',`);
        console.log(`    SUI: '${suiAddress}',`);
        console.log(`    TRON: '${tronAddress}',`);
        console.log(`    TON: '${tonAddress}',`);
        console.log(`    NEAR: '${nearAddress}',`);
        console.log(`    FILECOIN: '${filecoinAddress}',`);
        console.log(`};\n`);

        // Assertion to pass the test
        expect(evmAddress).toBeTruthy();
        expect(btcAddress).toBeTruthy();
    });
});
