import {createWallet} from "../chains/sui.ts";

test('test', () => {
    const wallet1 = createWallet({});
    console.log(wallet1);
})
