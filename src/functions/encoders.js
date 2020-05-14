module.exports = function (S) {
    let CM = S.__bitcoin_core_crypto.module;
    let BA = Buffer.alloc;
    let BC = Buffer.concat;
    let getBuffer = S.getBuffer;
    let ARGS = S.defArgs;
    let malloc = CM._malloc;
    let free = CM._free;
    let getValue = CM.getValue;

    S.encodeBase58 = (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', checkSum: false});
        m = getBuffer(m, A.encoding);
        if (A.checkSum) m = BC([m, S.doubleSha256(m).slice(0,4)]);
        if (m.length > 1073741823) throw new Error('encodeBase58 message is too long');

        let bP = malloc(m.length);
        let eS = m.length * 138 / 100 + 1;
        let oP = malloc(m.length * 138 / 100 + 1);
        CM.HEAPU8.set(m, bP);
        CM._EncodeBase58(bP, bP + m.length, oP);
        let out = new BA(eS);
        let q;
        for (q = 0; q <= eS; q++) {
            out[q] = getValue(oP + q, 'i8');
            if (out[q] === 0) break
        }
        free(bP);
        free(oP);
        return out.slice(0, q).toString();
    };

    S.decodeBase58 = (m, A = {}) => {
        ARGS(A, {hex: true, checkSum: false});
        if (!S.isString(m)) throw new Error('decodeBase58 string required');
        if (m.length > 2147483647) throw new Error('decodeBase58 string is too long');
        let mB = new BA(m.length + 1);
        mB.write(m);
        mB.writeInt8(0, m.length);
        let bP = malloc(mB.length);
        let oLP = malloc(4);
        let oP = malloc(Math.ceil(m.length * 733 / 1000) + 2);
        CM.HEAPU8.set(mB, bP);
        let r = CM._DecodeBase58(bP, oP, oLP);
        free(bP);
        if (r) {
            let oL = CM.getValue(oLP, 'i32');
            free(oLP);
            let out = new BA(oL);
            for (let q = 0; q <= oL; q++) out[q] = getValue(oP + q, 'i8');
            free(oP);
            if (A.checkSum) out = out.slice(0, -4);
            return (A.hex) ? out.hex() : out;
        }
        free(oP);
        free(oLP);
        return "";
    };

    S.rebaseBits = (data, fromBits, toBits, pad) => {
        if (pad === undefined) pad = true;
        let acc = 0, bits = 0, ret = [];
        let maxv = (1 << toBits) - 1;
        let max_acc = (1 << (fromBits + toBits - 1)) - 1;
        for (let i = 0; i < data.length; i++) {
            let value = data[i];
            if ((value < 0) || (value >> fromBits)) throw("invalid bytes");
            acc = ((acc << fromBits) | value) & max_acc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.push((acc >> bits) & maxv);
            }
        }
        if (pad === true) {
            if (bits)
                ret.push((acc << (toBits - bits)) & maxv);
        } else if ((bits >= fromBits) || ((acc << (toBits - bits)) & maxv))
            throw("invalid padding");
        return ret
    };

    S.rebase_5_to_8 = function (data, pad) {
        if (pad === undefined) pad = true;
        return S.rebaseBits(data, 5, 8, pad);
    };

    S.rebase_8_to_5 = (data, pad) => {
        if (pad === undefined) pad = true;
        return S.rebaseBits(data, 8, 5, pad);
    };

    S.rebase_32_to_5 = (data) => {
        if (typeof (data) !== "string") data = S.bytesToString(data);
        let b = [];
        try {
            for (let i = 0; i < data.length; i++) b.push(S.INT_BASE32_MAP[data[i]]);
        } catch (err) {
            throw("Non base32 characters");
        }
        return b;
    };

    S.rebase_5_to_32 = (data, bytes) => {
        if (bytes === undefined) bytes = true;
        let r = [];
        for (let i = 0; i < data.length; i++) r.push(S.BASE32_INT_MAP[data[i]]);
        return (bytes === true) ? r : S.bytesToString(r);
    };

    S.bech32Polymod = (values) => {
        let generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let chk = 1;
        for (let i = 0; i < values.length; i++) {
            let top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ values[i];
            for (let k = 0; k < 5; k++) {
                if ((top >> k) & 1) chk ^= generator[k];
                else chk ^= 0;
            }
        }
        return chk ^ 1;
    };
};