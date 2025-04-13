import {createWallet} from "../chains/aptos.ts";

test('test', () => {
    const wallet = createWallet({length: 128});
    console.log(wallet);
})
//{
//       mnemonic: 'ocean medal extend notice power where require endless shaft tiny dose odor',
//       privateKey: 'f52b1bbfe4a2dfab1c38357a2acf4cf5ee3c99d080567f3f579ba7b34b03f807',
//       publicKey: '03056be98c8463f5cfa766a31fc7704d31b81853f6f5a730e067d53c4b6cac90d2',
//       address: '5cde50628c933a049e4bdf55f871ba0c64344ee5'
//     }