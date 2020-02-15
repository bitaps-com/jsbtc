module.exports = function (constants, crypto, tools) {
    let Buffer = tools.Buffer;
    let isBuffer = tools.isBuffer;
    let malloc = crypto.module._malloc;
    let free = crypto.module._free;
    let getValue = crypto.module.getValue;
    return {
        encodeBase58: function (msg, named_args = {msgNotHex: false}) {
            if (!isBuffer(msg)) {
                if (tools.isString(msg)) {
                    msg = Buffer.from(msg, (!named_args.msgNotHex) && (tools.isHex(msg)) ? 'hex' : 'utf8');
                } else {
                    msg = Buffer.from(msg);
                }
            }
            if (msg.length > 1073741823) throw new Error('encodeBase58 message is too long');

            let bufPointer = malloc(msg.length);
            let estimateSize = msg.length * 138 / 100 + 1;
            let outPointer = malloc(msg.length * 138 / 100 + 1);
            crypto.module.HEAPU8.set(msg, bufPointer);
            crypto.module._EncodeBase58(bufPointer, bufPointer + msg.length, outPointer);
            let out = new Buffer.alloc(estimateSize);
            let q;
            for (q = 0; q <= estimateSize; q++) {
                out[q] = getValue(outPointer + q, 'i8');
                if (out[q] == 0) {
                    break
                }
            }
            free(bufPointer);
            free(outPointer);
            return out.slice(0, q).toString();
        },
        decodeBase58: function (msg, named_args = {hex: true, msgNotHex: false}) {
            if (!tools.isString(msg)) throw new Error('decodeBase58 string required');
            if (msg.length > 2147483647) throw new Error('decodeBase58 string is too long');
            let m = new Buffer.alloc(msg.length + 1);
            m.write(msg);
            m.writeInt8(0, msg.length);
            let bufPointer = malloc(m.length);
            let outLengthPointer = malloc(4);
            let outPointer = malloc(Math.ceil(msg.length * 733 / 1000) + 2);
            crypto.module.HEAPU8.set(m, bufPointer);
            crypto.module._DecodeBase58(bufPointer, outPointer, outLengthPointer);
            let outLength = crypto.module.getValue(outLengthPointer, 'i32');
            let out = new Buffer.alloc(outLength);
            for (let q = 0; q <= outLength; q++) out[q] = getValue(outPointer + q, 'i8');
            free(bufPointer);
            free(outLengthPointer);
            free(outPointer);
            return (named_args.hex) ? out.toString('hex') : out;
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