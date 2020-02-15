const Buffer = require('buffer/').Buffer;
const isBuffer = require('is-buffer');
const BN = require('bn.js');
const window = require('global/window');
let nodeCrypto = false;
try {
    nodeCrypto = require('crypto');
} catch (e) {

}

const BNZerro = new BN(0);

let  isHex = s => Boolean(/^[0-9a-fA-F]+$/.test(s) && !(s.length % 2));

function isString (value) {
    return typeof value === 'string' || value instanceof String;
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

function intToBytes(x, n) {
        let bytes = [];
        let i = n;
        do {
            bytes[--i] = x & (255);
            x = x >> 8;
        } while (i);
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
    stringToBytes
};