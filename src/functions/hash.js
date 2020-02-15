module.exports = function (crypto, tools) {
    let Buffer = tools.Buffer;
    let isBuffer = tools.isBuffer;
    let malloc = crypto.module._malloc;
    let free = crypto.module._free;
    let BN = tools.BN;
    let getValue = crypto.module.getValue;
    return {
        sha256: function (msg, named_args = {hex: false, msgNotHex: false}) {
            if (named_args.hex===undefined) named_args.hex=false;
            if (named_args.msgNotHex===undefined) named_args.msgNotHex=false;
            if (!isBuffer(msg)) {
                if (tools.isString(msg)) {
                    msg = Buffer.from(msg, (!named_args.msgNotHex)&&(tools.isHex(msg)) ? 'hex' : 'utf8');
                } else {
                    msg = Buffer.from(msg);
                }
            }
            let bufPointer = malloc(msg.length);
            let outPointer = malloc(32);
            crypto.module.HEAPU8.set(msg, bufPointer);
            crypto.module._single_sha256(bufPointer,msg.length, outPointer);
            let out = new Buffer.alloc(32);
            for (let i=0; i<32; i++) {
                out[i] = crypto.module.getValue(outPointer + i, 'i8');
            }
            free(bufPointer);
            free(outPointer);
            return (named_args.hex)? out.toString('hex'): out;
        },
        doubleSha256: function (msg, named_args = {hex: false, msgNotHex: false}) {
            if (named_args.hex===undefined) named_args.hex=false;
            if (named_args.msgNotHex===undefined) named_args.msgNotHex=false;
            if (!isBuffer(msg)) {
                if (tools.isString(msg)) {
                    msg = Buffer.from(msg, (!named_args.msgNotHex)&&(tools.isHex(msg)) ? 'hex' : 'utf8');
                } else {
                    msg = Buffer.from(msg);
                }
            }
            let bufPointer = malloc(msg.length);
            let outPointer = malloc(32);
            crypto.module.HEAPU8.set(msg, bufPointer)
            crypto.module._double_sha256(bufPointer,msg.length, outPointer);
            let out = new Buffer.alloc(32)
            for (let i=0; i<32; i++) {
                out[i] = crypto.module.getValue(outPointer + i, 'i8');
            }
            free(bufPointer);
            free(outPointer);
            return (named_args.hex)? out.toString('hex'): out;
        },
        siphash: function (msg, named_args = {v0: tools.BNZerro, v1: tools.BNZerro, msgNotHex: false}) {
            if (named_args.v0 === undefined) named_args.v0 = tools.BNZerro;
            if (named_args.v1 === undefined) named_args.v1 = tools.BNZerro;
            if (named_args.msgNotHex === undefined) named_args.msgNotHex = false;
            if (!isBuffer(msg)) {
                if (tools.isString(msg)) {
                    msg = Buffer.from(msg, (!named_args.msgNotHex)&&(tools.isHex(msg)) ? 'hex' : 'utf8');
                } else {
                    msg = Buffer.from(msg);
                }
            }

            if (!(named_args.v1 instanceof tools.BN) || !(named_args.v0 instanceof tools.BN)) {
                throw new Error('siphash init vectors v0, v1 must be BN');
            }
            let v0b = named_args.v0.toArrayLike(Uint8Array, 'le', 8)
            let v1b = named_args.v1.toArrayLike(Uint8Array, 'le', 8)
            let bufPointer = malloc(msg.length);
            let v0Pointer = malloc(8);
            let v1Pointer = malloc(8);
            let outPointer = malloc(8);
            crypto.module.HEAPU8.set(msg, bufPointer);
            crypto.module.HEAPU8.set(v0b, v0Pointer);
            crypto.module.HEAPU8.set(v1b, v1Pointer);
            crypto.module._siphash(v0Pointer, v1Pointer, bufPointer,msg.length, outPointer);
            let out = new Buffer.alloc(9)
            for (let i=0; i<8; i++) {
                out[8-i] = crypto.module.getValue(outPointer + i, 'i8');
            }
            free(bufPointer);
            free(outPointer);
            return new BN(out);
        },
        ripemd160: function (msg, named_args = {hex: false, msgNotHex: false}) {
            if (named_args.hex===undefined) named_args.hex=false;
            if (named_args.msgNotHex===undefined) named_args.msgNotHex=false;
            if (!isBuffer(msg)) {
                if (tools.isString(msg)) {
                    msg = Buffer.from(msg, (!named_args.msgNotHex)&&(tools.isHex(msg)) ? 'hex' : 'utf8');
                } else {
                    msg = Buffer.from(msg);
                }
            }
            let bufPointer = malloc(msg.length);
            let outPointer = malloc(32);
            crypto.module.HEAPU8.set(msg, bufPointer)
            crypto.module.__ripemd160(bufPointer,msg.length, outPointer);
            let out = new Buffer.alloc(20)
            for (let i=0; i<20; i++) {
                out[i] = crypto.module.getValue(outPointer + i, 'i8');
            }
            free(bufPointer);
            free(outPointer);

            return (named_args.hex)? out.toString('hex'): out;
        },
        hash160: function (msg, named_args = {hex: false, msgNotHex: false}) {
            if (named_args.hex===undefined) named_args.hex=false;
            if (named_args.msgNotHex===undefined) named_args.msgNotHex=false;
            return this.ripemd160(this.sha256(msg, {hex:false, msgNotHex: named_args.msgNotHex}),
                {hex:named_args.hex });
        }
    }
};