import {createWallet} from "../chains/solana.ts";

test('solana test', () => {
    const wallet1 = createWallet({length:256});
    console.log(wallet1);
})
