module.exports = function (constants, crypto, tools) {
    let Buffer = tools.Buffer;
    let CM = crypto.module;
    let getBuffer = tools.getBuffer;
    let defArgs = tools.defArgs;
    let malloc = CM._malloc;
    let free = CM._free;
    let getValue = CM.getValue;
    return {
        encodeBase58: (m, A = {})=> {
            defArgs(A, {encoding: 'hex|utf8'});
            m = getBuffer(m, A.encoding);
            if (m.length > 1073741823) throw new Error('encodeBase58 message is too long');

            let bP = malloc(m.length);
            let eS = m.length * 138 / 100 + 1;
            let oP = malloc(m.length * 138 / 100 + 1);
            CM.HEAPU8.set(m, bP);
            CM._EncodeBase58(bP, bP + m.length, oP);
            let out = new Buffer.alloc(eS);
            let q;
            for (q = 0; q <= eS; q++) {
                out[q] = getValue(oP + q, 'i8');
                if (out[q] === 0)  break
            }
            free(bP);
            free(oP);
            return out.slice(0, q).toString();
        },
        decodeBase58: (m, A = {}) => {
            defArgs(A, {hex: true});
            if (!tools.isString(m)) throw new Error('decodeBase58 string required');
            if (m.length > 2147483647) throw new Error('decodeBase58 string is too long');
            let mB = new Buffer.alloc(m.length + 1);
            mB.write(m);
            mB.writeInt8(0, m.length);
            let bP = malloc(mB.length);
            let oLP = malloc(4);
            let oP = malloc(Math.ceil(m.length * 733 / 1000) + 2);
            CM.HEAPU8.set(mB, bP);
            CM._DecodeBase58(bP, oP, oLP);
            let oL = CM.getValue(oLP, 'i32');
            let out = new Buffer.alloc(oL);
            for (let q = 0; q <= oL; q++) out[q] = getValue(oP + q, 'i8');
            free(bP);
            free(oLP);
            free(oP);
            return (A.hex) ? out.hex() : out;
        },
        rebaseBits: function (data, frombits, tobits, pad) {
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
            } else if ((bits >= frombits) || ((acc << (tobits - bits)) & maxv))
                throw("invalid padding");
            return ret
        },
        rebase_5_to_8: function (data, pad) {
            if (pad === undefined) pad = true;
            return this.rebaseBits(data, 5, 8, pad);
        },
        rebase_8_to_5: function (data, pad) {
            if (pad === undefined) pad = true;
            return this.rebaseBits(data, 8, 5, pad);
        },
        rebase_32_to_5: function (data) {
            if (typeof (data) !== "string") data = tools.bytesToString(data);
            let b = [];
            try {
                for (let i = 0; i < data.length; i++) b.push(constants.INT_BASE32_MAP[data[i]]);
            } catch (err) {
                throw("Non base32 characters");
            }
            return b
        },
        rebase_5_to_32: function (data, bytes) {
            if (bytes === undefined) bytes = true;
            let r = [];
            for (let i = 0; i < data.length; i++) r.push(constants.BASE32_INT_MAP[data[i]]);
            if (bytes === true) {
                return r;
            } else {
                return tools.bytesToString(r);
            }
        },
        bech32Polymod: function (values) {
            let generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
            let chk = 1;
            for (let i = 0; i < values.length; i++) {
                let top = chk >> 25;
                chk = (chk & 0x1ffffff) << 5 ^ values[i];
                for (let k = 0; k < 5; k++) {
                    if ((top >> k) & 1) {
                        chk ^= generator[k];
                    } else {
                        chk ^= 0
                    }
                }

            }
            return chk ^ 1;
        }
    }
};