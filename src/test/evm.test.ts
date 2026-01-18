import {createWallet, getAddressByPrivateKey} from "../chains/evm";
import {sha256}  from '@noble/hashes/sha256'
import {sha512} from "@noble/hashes/sha512";
import {bytesToHex, utf8ToBytes} from "@noble/hashes/utils";
import {Versions} from "@scure/bip32/index";
import {hmac} from "@noble/hashes/hmac";
import {mnemonicToSeedSync} from "bip39";
import {HDKey} from "@scure/bip32";
function lpad(str:string, padString:string, length:number) {
    while (str.length < length) {
        str = padString + str;
    }
    return str;
}
function bytesToBinary(bytes:any[]) {
    return bytes.map((x) => lpad(x.toString(2), '0', 8)).join('');
}
function deriveChecksumBits(entropyBuffer:Buffer) {
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    const hash = sha256(Uint8Array.from(entropyBuffer));

    return bytesToBinary(Array.from(hash)).slice(0, CS);
}
test('test', () => {
    const wallet = createWallet({length: 128});
    // console.log(wallet);
    const cr = typeof globalThis === 'object' ? (globalThis as any).crypto : null;
    const rb = cr.getRandomValues(new Uint8Array(128/8))
    console.log(rb)
    /**
     * 生成助记词
     * 1 传入要生成的熵的长度
     * 2 调用系统级别的加密安全随机数生成函数
     * 3 将生成的熵转为二进制字符串
     * 4 从原始随机熵派生出助记词所需的校验和的二进制字符串（将熵进行sha256运算得到hash，并取其前[熵的字节长度/32]位作为校验和）
     * 5 将熵和检验和的二进制字符串相加并以11位进行分割，得到一个助记词下标数组
     * 6 将上述数组对应到组词列表获得助记词
     *
     * 助记词派主密钥
     * 7 将助记词和密码字符串（如果有）通过NFKD规则标准化并转为字节（密码字符串加盐mnemonic）
     * 8 调用pbkdf2，将两者通过sha512运算迭代2048次得到64字节的种子
     *
     */


    const rng = Buffer.from(rb)
    console.log('rng',rng)
    const entropyBits = bytesToBinary(Array.from(rng));
    console.log('entropyBits',entropyBits);
    const checksumBits = deriveChecksumBits(rng);
    console.log('checksumBits',checksumBits);


    const bits = entropyBits + checksumBits;
    console.log(bits);
    const chunks = bits.match(/(.{1,11})/g);

    console.log('chunks',chunks);
    const words = chunks?.map((binary) => {
        return  parseInt(binary,2);
    });
    console.log('words',words);

    const MASTER_SECRET = utf8ToBytes('Bitcoin seed');
    // Bitcoin hardcoded by default
    const BITCOIN_VERSIONS: Versions = { private: 0x0488ade4, public: 0x0488b21e };
    const HARDENED_OFFSET: number = 0x80000000;

    if(words){

        const seed = mnemonicToSeedSync(words.toString());

        const I = hmac(sha512, MASTER_SECRET, seed);
        const hk =  new HDKey({
            chainCode: I.slice(32),
            privateKey: I.slice(0, 32),
        });

        console.log('hk',hk);
        if(hk.privateKey){
            const address = getAddressByPrivateKey(bytesToHex(hk.privateKey));
            console.log('address',address);
            console.log('bytesToHex(hk.privateKey)',bytesToHex(hk.privateKey));
        }
    }

})
