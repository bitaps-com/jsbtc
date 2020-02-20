const Buffer = require('buffer/').Buffer;
const isBuffer = Buffer.isBuffer;
const BN = require('bn.js');
const window = require('global/window');
let nodeCrypto = false;
try {
    nodeCrypto = require('crypto');
} catch (e) {

}

Buffer.prototype.seek = function (n) {
    this.__offset = (n > this.length)  ? this.length: n;
};

Buffer.prototype.tell = function ()  {this.__offset;};

Buffer.prototype.read = function (n) {
    if (this.__offset===undefined) this.__offset = 0;
    if (this.__offset===this.length) return Buffer.from([]);
    let m = this.__offset + n;
    if (m > this.length) m = this.length;
    let r = this.slice(this.__offset, m);
    this.__offset = m;
    return r;
};

Buffer.prototype.readVarInt = function () {
    if (this.__offset===undefined) this.__offset = 0;
    if (this.__offset===this.length) return Buffer.from([]);
    let l = this[this.__offset];
    if (l < 253) l = 1;
    else if (l === 253) l = 3;
    else if (l === 254) l = 5;
    else if (l === 255) l = 9;
    return this.read(l);

};

Buffer.prototype.readInt = function (n, byte_order='little') {
    if (this.__offset===undefined) this.__offset = 0;
    if (this.__offset===this.length) return 0;
    if ((this.__offset + n) > this.length) n = this.length - this.__offset;
    let r;
    if (byte_order === 'little') r = this.readUIntLE(this.__offset, n);
    else r = this.readUIntBE(this.__offset, n);
    this.__offset += n;
    return r;
};



let readVarInt = (s) => {
    let l = s[s.__offset];
    if (l < 253) l = 1;
    else if (l === 253) l = 3;
    else if (l === 254) l = 5;
    else if (l === 255) l = 9;
    return s.read(l);
};

Buffer.prototype.hex = function () {
    return this.toString('hex');
};



const BNZerro = new BN(0);

let  isHex = s => Boolean(/^[0-9a-fA-F]+$/.test(s) && !(s.length % 2));

function getBuffer(m, encoding='hex') {
    if (isBuffer(m)) {
        if (m.read === undefined) return Buffer.from(m);
        return m;
    }
    if (isString(m)) {
        if (m.length === 0) return Buffer(0);
        encoding = encoding.split('|');
        for (let e of encoding) {
            if (e === 'hex') { if (isHex(m)) return Buffer.from(m, e);}
            else if (e === 'utf8')  return Buffer.from(m, e);
        }
        throw new Error(encoding + ' encoding required :' + encoding);
    }
    return Buffer.from(m);
}

function isString (value) {
    return typeof value === 'string' || value instanceof String;
}

function defArgs(named_args, values) {
    for (let key in values)
        if (named_args[key]===undefined) named_args[key] = values[key];
}

function bytesToHex(bytes) {
        return arrBytesToHex(bytes);
    }

function hexToBytes(hex) {
        if (hex.length % 2 === 1) throw new Error("hexToBytes can't have a string with an odd number of characters.");
        if (hex.indexOf('0x') === 0) hex = hex.slice(2);
        return hex.match(/../g).map(function (x) {
            return parseInt(x, 16)
        })
    }


function arrBytesToHex(bytes) {
        return bytes.map(function (x) {
            return x.toString(16).padStart(2, '0')
        }).join('')
    }

function bytesToString(bytes) {
        return bytes.map(function (x) {
            return String.fromCharCode(x)
        }).join('')
    }


function stringToBytes(str) {
        return str.split('').map(function (x) {
            return x.charCodeAt(0)
        })
    }

function bytesToStringUTF8(bytes) {
        return decodeURIComponent(escape(bytesToString(bytes)))
    }


function stringUTF8ToBytes(str) {
        return stringToBytes(unescape(encodeURIComponent(str)))
    }

function intToBytes(x, n, byte_order = "little") {
        let bytes = [];
        let i = n;
        if (n === undefined) throw new Error('bytes count required');
        if ((byte_order!=="big")&& (byte_order!=="little")) throw new Error('invalid byte order');
        let b = (byte_order === "big");
        do {
            (b) ? bytes.unshift(x & (255)): bytes.push(x & (255))
            x = x >> 8;
        } while (--i);

        return bytes;
    }

function intToVarInt(i) {
    let r ;
    if (i instanceof BN) {
        if (i.lt(0xfd)) r = i.toArrayLike(Array, 'le',1);
        else if (i.lt(0xffff)) r = [0xfd].concat(i.toArrayLike(Array, 'le', 2));
        else if (i.lt(0xffffffff)) r = [0xfe].concat(i.toArrayLike(array_object, 'le', 4));
        else r = [0xff].concat(i.toArrayLike(array_object, 'le', 8));
        return  r;
    }
    else if (!isNaN(i)) {
        if (i < 0xfd) r = [i];
        else if (i < 0xffff) r = [0xfd].concat(intToBytes(i, 2, 'little'));
        else if (i < 0xffffffff) r = [0xfe].concat(intToBytes(i, 4, 'little'));
        else  r = [0xff].concat(intToBytes(i, 8, 'little'));
        return r;
    }
    else {
        throw new Error('invalid argument type', i);
    }
}

function varIntToInt(s, bn = false) {
    let r;
    if (s[0] < 0xfd) r = new BN(s[0]);
    else if (s[0] < 0xffff) r =  new BN(s.slice(1,3), 'le');
    else if (s[0] < 0xffffffff) r = new BN(s.slice(1,4), 'le');
    else r = new BN(s.slice(1,8), 'le');
    if (bn) return r;
    return r.toNumber();
}

let varIntLen = (b) =>  (b[0] < 0xfd) ? 1: (b[0] < 0xffff) ? 2 : (b[0] < 0xffffffff) ? 4 : 8;

let rh2s = (s) => Buffer.from(s).reverse().hex();
let s2rh = (s) => Buffer.from(s, 'hex').reverse();

module.exports = {
    isHex,
    Buffer,
    isBuffer,
    isString,
    window,
    BN,
    BNZerro,
    nodeCrypto,
    bytesToHex,
    intToBytes,
    bytesToString,
    stringToBytes,
    defArgs,
    getBuffer,
    hexToBytes,
    intToVarInt,
    varIntToInt,
    varIntLen,
    readVarInt,
    rh2s,
    s2rh
};