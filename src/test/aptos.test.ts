import {createWallet} from "../chains/aptos.ts";

test('test', () => {
    const wallet = createWallet({length: 128});
    console.log(wallet);
})
