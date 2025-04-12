import fromSeed ,{ BIP32API} from 'bip32';
import { Network } from 'bitcoinjs-lib';

export function deriveFromSeed(seed: Buffer, network?: Network): BIP32API {
    return fromSeed(seed);
}