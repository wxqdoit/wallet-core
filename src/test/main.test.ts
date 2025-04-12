import {createWallet} from "../chains/evm";

test('test', () => {
    const wallet = createWallet({length: 128});
    console.log(wallet);
})