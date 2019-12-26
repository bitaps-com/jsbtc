var constants = require('../constants.js');


function base58encode(B) {
    let d = [], s = "";
    let i, j, c, n;
    for (i in B) {
        j = 0, c = B[i];
        s += c || s.length ^ i ? "" : 1;
        while (j in d || c) {
            n = d[j];
            n = n ? n * 256 + c : c;
            c = n / 58 | 0;
            d[j] = n % 58;
            j++
        }
    }
    while (j--) s += constants.base58Alphabet[d[j]];
    return s
}

function base58decode(S) {
    let d = [], b = [], i, j, c, n;
    for (i in S) {
        if (typeof(S[i]) === 'function') break;
        j = 0, c = constants.base58Alphabet.indexOf(S[i]);
        if (c < 0) return undefined;
        c || b.length ^ i ? i : b.push(0);
        while (j in d || c) {
            n = d[j];
            n = n ? n * 58 + c : c;
            c = n >> 8;
            d[j] = n % 256;
            j++
        }
    }
    while (j--) b.push(d[j]);
    return b
}

function rebasebits(data, frombits, tobits, pad) {
    if (pad === undefined) pad = true;
    let acc = 0;
    let bits = 0;
    let ret = [];
    let maxv = (1 << tobits) - 1;
    let max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (let i = 0; i < data.length; i++) {
        let value = data[i];
        if ((value < 0) || (value >> frombits)) throw("invalid bytes");
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            ret.push((acc >> bits) & maxv);
        }
    }

    if (pad === true) {
        if (bits)
            ret.push((acc << (tobits - bits)) & maxv);
    }
    else if ((bits >= frombits) || ((acc << (tobits - bits)) & maxv))
        throw("invalid padding");
    return ret
}

function rebase_5_to_8(data, pad) {
    if (pad === undefined) pad = true;
    return rebasebits(data, 5, 8, pad);
}

function rebase_8_to_5(data, pad) {
    if (pad === undefined) pad = true;
    return rebasebits(data, 8, 5, pad);
}

function rebase_32_to_5(data) {
    if (typeof(data) !== "string") data = bytesToString(data);
    let b = [];
    try {
        for (let i = 0; i < data.length; i++) b.push(int_base32_map[data[i]]);
    }
    catch (err) {
        throw("Non base32 characters");
    }
    return b
}

function rebase_5_to_32(data, bytes) {
    if (bytes === undefined) bytes = true;
    let r = [];
    for (let i = 0; i < data.length; i++) r.push(base32_int_map[data[i]]);
    if (bytes === true) {
        return r;
    }
    else {
        return tools.bytesToString(r);
    }
}

function bech32_polymod(values) {
    let generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (let i = 0; i < values.length; i++) {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[i];
        for (let k = 0; k < 5; k++) {
            if ((top >> k) & 1) {
                chk ^= generator[k];
            }
            else {
                chk ^= 0
            }
        }

    }
    return chk ^ 1;
}


module.exports = {
    base58encode,
    base58decode,
    rebasebits,
    rebase_5_to_8,
    rebase_8_to_5,
    rebase_32_to_5,
    rebase_5_to_32,
    bech32_polymod
};