
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
    bytesToHex,
    hexToBytes,
    arrBytesToHex,
    bytesToString,
    bytesToStringUTF8,
    stringUTF8ToBytes,
    intToBytes
};