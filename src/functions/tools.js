module.exports = function (S) {
    S.Buffer = require('buffer/').Buffer;
    S.isBuffer = S.Buffer.isBuffer;
    S.BN = require('bn.js');
    S.__nodeCrypto = false;
    try {
        S.__nodeCrypto = require('crypto');
    } catch (e) {
    }

    S.Buffer.prototype.seek = function (n) {
        this.__offset = (n > this.length) ? this.length : n;
    };
    S.Buffer.prototype.tell = function () {
        this.__offset;
    };

    S.Buffer.prototype.read = function (n) {
        if (this.__offset === undefined) this.__offset = 0;
        if (this.__offset === this.length) return S.Buffer.from([]);
        let m = this.__offset + n;
        if (m > this.length) m = this.length;
        let r = this.slice(this.__offset, m);
        this.__offset = m;
        return r;
    };

    S.Buffer.prototype.readVarInt = function () {
        if (this.__offset === undefined) this.__offset = 0;
        if (this.__offset === this.length) return S.Buffer.from([]);
        let l = this[this.__offset];
        if (l < 253) l = 1;
        else if (l === 253) l = 3;
        else if (l === 254) l = 5;
        else if (l === 255) l = 9;
        return this.read(l);
    };

    S.Buffer.prototype.readInt = function (n, byte_order = 'little') {
        if (this.__offset === undefined) this.__offset = 0;
        if (this.__offset === this.length) return 0;
        if ((this.__offset + n) > this.length) n = this.length - this.__offset;
        let r;
        if (byte_order === 'little') r = this.readUIntLE(this.__offset, n);
        else r = this.readUIntBE(this.__offset, n);
        this.__offset += n;
        return r;
    };

    S.Buffer.prototype.hex = function () {
        return this.toString('hex');
    };

    S.getWindow = () => {
        if (typeof window !== "undefined") return window;
        if (typeof global !== "undefined") return  global;
        if (typeof self !== "undefined") return self;
        return  {};
    };

    S.readVarInt = (s) => {
        let l = s[s.__offset];
        if (l < 253) l = 1;
        else if (l === 253) l = 3;
        else if (l === 254) l = 5;
        else if (l === 255) l = 9;
        return s.read(l);
    };


    S.BNZerro = new S.BN(0);

    S.isHex = s => Boolean(/^[0-9a-fA-F]+$/.test(s) && !(s.length % 2));

    S.getBuffer = function (m, encoding = 'hex') {
        if (S.isBuffer(m)) {
            if (m.read === undefined) return S.Buffer.from(m);
            return m;
        }
        if (isString(m)) {
            if (m.length === 0) return S.Buffer(0);
            encoding = encoding.split('|');
            for (let e of encoding) {
                if (e === 'hex') {
                    if (S.isHex(m)) return S.Buffer.from(m, e);
                } else if (e === 'utf8') return S.Buffer.from(m, e);
            }
            throw new Error(encoding + ' encoding required :' + encoding);
        }
        return S.Buffer.from(m);
    };

    S.isString = function (value) {
        return typeof value === 'string' || value instanceof String;
    };

    S.defArgs = function (n, v) {
        for (let k in v) if (n[k] === undefined) n[k] = v[k];
    };


    S.bytesToString = function (bytes) {
        return bytes.map(function (x) {
            return String.fromCharCode(x)
        }).join('')
    };

    S.hexToBytes = (hex) => {
        if (hex.length % 2 === 1) throw new Error("hexToBytes can't have a string with an odd number of characters.");
        if (hex.indexOf('0x') === 0) hex = hex.slice(2);
        return hex.match(/../g).map(function (x) {
            return parseInt(x, 16)
        })
    };

    S.stringToBytes = function (str) {
        return str.split('').map(function (x) {
            return x.charCodeAt(0)
        })
    };

    S.bytesToStringUTF8 = function bytesToStringUTF8(bytes) {
        return decodeURIComponent(escape(bytesToString(bytes)))
    }


    S.stringUTF8ToBytes = function (str) {
        return S.stringToBytes(unescape(encodeURIComponent(str)))
    }

    S.intToBytes = function (x, n, byte_order = "little") {
        let bytes = [];
        let i = n;
        if (n === undefined) throw new Error('bytes count required');
        if ((byte_order !== "big") && (byte_order !== "little")) throw new Error('invalid byte order');
        let b = (byte_order === "big");
        if (n <= 4)
            do {
                (b) ? bytes.unshift(x & (255)) : bytes.push(x & (255))
                x = x >> 8;
            } while (--i);
        else {
            x = new S.BN(x);
            bytes = x.toArrayLike(Array, (b) ? 'be' : 'le', n);
        }
        return bytes;
    };

    S.intToVarInt = function (i) {
        let r;
        if (i instanceof S.BN) {
            if (i.lt(0xfd)) r = i.toArrayLike(Array, 'le', 1);
            else if (i.lt(0xffff)) r = [0xfd].concat(i.toArrayLike(Array, 'le', 2));
            else if (i.lt(0xffffffff)) r = [0xfe].concat(i.toArrayLike(Array, 'le', 4));
            else r = [0xff].concat(i.toArrayLike(Array, 'le', 8));
            return r;
        } else if (!isNaN(i)) {
            if (i < 0xfd) r = [i];
            else if (i < 0xffff) r = [0xfd].concat(S.intToBytes(i, 2, 'little'));
            else if (i < 0xffffffff) r = [0xfe].concat(S.intToBytes(i, 4, 'little'));
            else r = [0xff].concat(S.intToBytes(i, 8, 'little'));
            return r;
        } else {
            throw new Error('invalid argument type', i);
        }
    }

    S.varIntToInt = function (s, bn = false) {
        let r;
        if (s[0] < 0xfd) r = new S.BN(s[0]);
        else if (s[0] < 0xffff) r = new S.BN(s.slice(1, 3), 'le');
        else if (s[0] < 0xffffffff) r = new S.BN(s.slice(1, 4), 'le');
        else r = new S.BN(s.slice(1, 8), 'le');
        if (bn) return r;
        return r.toNumber();
    };

    S.varIntLen = (b) => (b[0] < 0xfd) ? 1 : (b[0] < 0xffff) ? 2 : (b[0] < 0xffffffff) ? 4 : 8;

    S.rh2s = (s) => S.Buffer.from(s).reverse().hex();
    S.s2rh = (s) => S.Buffer.from(s, 'hex').reverse();

};