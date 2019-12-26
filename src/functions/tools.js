module.exports = {
    bytesToHex: function (bytes) {
        return arrBytesToHex(bytes);
    },

    hexToBytes: function (hex) {
        if (hex.length % 2 === 1) throw new Error("hexToBytes can't have a string with an odd number of characters.");
        if (hex.indexOf('0x') === 0) hex = hex.slice(2);
        return hex.match(/../g).map(function (x) {
            return parseInt(x, 16)
        })
    },


    arrBytesToHex: function (bytes) {
        return bytes.map(function (x) {
            return padLeft(x.toString(16), 2)
        }).join('')
    },

    bytesToString: function (bytes) {
        return bytes.map(function (x) {
            return String.fromCharCode(x)
        }).join('')
    },


    stringToBytes: function (str) {
        return str.split('').map(function (x) {
            return x.charCodeAt(0)
        })
    },

    bytesToStringUTF8: function (bytes) {
        return decodeURIComponent(escape(bytesToString(bytes)))
    },


    stringUTF8ToBytes: function (str) {
        return stringToBytes(unescape(encodeURIComponent(str)))
    },

    intToBytes: function (x, n) {
        let bytes = [];
        let i = n;
        do {
            bytes[--i] = x & (255);
            x = x >> 8;
        } while (i);
        return bytes;
    }
};