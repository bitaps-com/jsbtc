const Buffer = require('buffer/').Buffer;
const isBuffer = Buffer.isBuffer;
const BN = require('bn.js');
const window = require('global/window');
let nodeCrypto = false;
try {
    nodeCrypto = require('crypto');
} catch (e) {

}

Buffer.prototype.read = function (n) {
    if (this.__offset===undefined) this.__offset = 0;
    if (this.__offset===this.length) return Buffer.from([]);
    let m = this.__offset + n;
    if (m > this.length) m = this.length;
    let r = this.slice(this.__offset, m);
    this.__offset = m;
    return r;
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
        encoding = encoding.split('|');
        for (let e of encoding) {
            if (e === 'hex') { if (isHex(m)) return Buffer.from(m, e);}
            else if (e === 'utf8')  return Buffer.from(m, e);
        }
        throw new Error(encoding + ' encoding required');
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

function intToBytes(x, n, byte_order = "big") {
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
    hexToBytes
};