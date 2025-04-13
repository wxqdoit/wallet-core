// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// This is adapted from https://github.com/alepop/ed25519-hd-key replacing create-hmac
// with @noble/hashes to be browser compatible.

import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import {ED25519_CURVE, HARDENED_OFFSET, pathRegex} from "../constans";




type Keys = {
    key: Uint8Array<ArrayBufferLike>;
    chainCode: Uint8Array<ArrayBufferLike>;
};




const replaceDerive = (val: string): string => val.replace("'", '');

const getMasterKeyFromSeed = (seed: Uint8Array<ArrayBufferLike>): Keys => {
    const h = hmac(sha512, new TextEncoder().encode(ED25519_CURVE),seed);
    const IL = h.slice(0, 32);
    const IR = h.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};

const CKDPriv = ({ key, chainCode }: Keys, index: number): Keys => {
    const indexBuffer = new ArrayBuffer(4);
    const cv = new DataView(indexBuffer);
    cv.setUint32(0, index);

    const data = new Uint8Array(1 + key.length + indexBuffer.byteLength);
    data.set(new Uint8Array(1).fill(0));
    data.set(key, 1);
    data.set(new Uint8Array(indexBuffer, 0, indexBuffer.byteLength), key.length + 1);

    const I = hmac(sha512, chainCode,data)
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};

const isValidPath = (path: string): boolean => {
    if (!pathRegex.test(path)) {
        return false;
    }
    return !path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .some(isNaN as any /* ts T_T*/);
};

export const derivePath = (path: string, seed:Uint8Array<ArrayBufferLike>, offset = HARDENED_OFFSET): Keys => {
    if (!isValidPath(path)) {
        throw new Error('Invalid derivation path');
    }

    const { key, chainCode } = getMasterKeyFromSeed(seed);
    const segments = path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .map((el) => parseInt(el, 10));

    return segments.reduce((parentKeys, segment) => CKDPriv(parentKeys, segment + offset), {
        key,
        chainCode,
    });
};