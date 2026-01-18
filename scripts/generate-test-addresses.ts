/**
 * Script to generate test addresses from persistent mnemonic
 */

import * as EVM from '../src/chains/evm';
import * as BTC from '../src/chains/btc';
import * as Solana from '../src/chains/solana';
import * as Aptos from '../src/chains/aptos';
import * as Sui from '../src/chains/sui';
import * as Tron from '../src/chains/tron';
import * as Ton from '../src/chains/ton';
import * as Near from '../src/chains/near';
import * as Filecoin from '../src/chains/filecoin';

const TEST_MNEMONIC = 'steak treat wait fog two seven pluck sting wife motor machine topic image humor tobacco noodle seven mail staff century swim mimic now february';

async function generateAddresses() {
    console.log('🔑 Generating test addresses from mnemonic...\n');

    // EVM
    const evmKeys = EVM.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/60'/0'/0/0");
    const evmAddress = EVM.getAddressByPrivateKey(evmKeys.privateKey);
    console.log('📗 EVM (Ethereum/BSC/Polygon):');
    console.log(`   Address: 0x${evmAddress}`);
    console.log(`   Private Key: ${evmKeys.privateKey}\n`);

    // Bitcoin
    const btcKeys = BTC.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/84'/0'/0'/0/0");
    const btcAddress = BTC.getAddressByPrivateKey(btcKeys.privateKey, 'p2wpkh');
    console.log('🟠 Bitcoin (Testnet):');
    console.log(`   Address: ${btcAddress}`);
    console.log(`   Private Key: ${btcKeys.privateKey}\n`);

    // Solana
    const solanaPrivateKey = Solana.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/501'/0'/0'");
    const solanaAddress = Solana.getAddressByPrivateKey(solanaPrivateKey);
    console.log('🟣 Solana (Devnet):');
    console.log(`   Address: ${solanaAddress}`);
    console.log(`   Private Key: ${solanaPrivateKey}\n`);

    // Aptos
    const aptosPrivateKey = Aptos.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/637'/0'/0'/0'");
    const aptosAddress = Aptos.getAddressByPrivateKey(aptosPrivateKey);
    console.log('⚫ Aptos (Devnet):');
    console.log(`   Address: ${aptosAddress}`);
    console.log(`   Private Key: ${aptosPrivateKey}\n`);

    // Sui
    const suiPrivateKey = Sui.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/784'/0'/0'/0'");
    const suiAddress = Sui.getAddressByPrivateKey(suiPrivateKey);
    console.log('🔵 Sui (Devnet):');
    console.log(`   Address: ${suiAddress}`);
    console.log(`   Private Key: ${suiPrivateKey}\n`);

    // TRON
    const tronKeys = Tron.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/195'/0'/0/0");
    const tronAddress = Tron.getAddressByPrivateKey(tronKeys.privateKey);
    console.log('🔴 TRON (Nile Testnet):');
    console.log(`   Address: ${tronAddress}`);
    console.log(`   Private Key: ${tronKeys.privateKey}\n`);

    // TON
    const tonPrivateKey = Ton.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/607'/0'/0'/0'");
    const tonAddress = Ton.getAddressByPrivateKey(tonPrivateKey);
    console.log('💎 TON (Testnet):');
    console.log(`   Address: ${tonAddress}`);
    console.log(`   Private Key: ${tonPrivateKey}\n`);

    // NEAR
    const nearPrivateKey = Near.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/397'/0'");
    const nearAddress = Near.getAddressByPrivateKey(nearPrivateKey);
    console.log('⚪ NEAR (Testnet):');
    console.log(`   Address: ${nearAddress}`);
    console.log(`   Private Key: ${nearPrivateKey}\n`);

    // Filecoin
    const filecoinKeys = Filecoin.getPrivateKeyByMnemonic(TEST_MNEMONIC, "m/44'/461'/0'/0/0", 'secp256k1');
    const filecoinAddress = Filecoin.getAddressByPrivateKey(filecoinKeys.privateKey, 'secp256k1');
    console.log('⚡ Filecoin (Calibration Testnet):');
    console.log(`   Address: ${filecoinAddress}`);
    console.log(`   Private Key: ${filecoinKeys.privateKey}\n`);

    console.log('✅ All addresses generated successfully!');
    console.log('\n📄 Update src/test/testnet-config.ts with these addresses.');
}

generateAddresses().catch(console.error);
