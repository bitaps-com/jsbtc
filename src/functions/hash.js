var tools = require('./tools.js');

function sha256(message, named_args) {
    let K = [];
    if (message.constructor === String) {
        message = tools.hexToBytes(message);
    }

    if (named_args === undefined) named_args= {};
    if (named_args.hex === undefined) named_args.hex = false;

    // Compute constants
    !function () {
        function isPrime(n) {
            let sqrtN = Math.sqrt(n);
            for (var factor = 2; factor <= sqrtN; factor++) {
                if (!(n % factor)) return false
            }
            return true
        }

        function getFractionalBits(n) {
            return ((n - (n | 0)) * 0x100000000) | 0
        }

        let n = 2;
        let nPrime = 0;
        while (nPrime < 64) {
            if (isPrime(n)) {
                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));
                nPrime++
            }
            n++;
        }
    }();

    // Reusable object
    let W = [];
    let processBlock = function (H, M, offset) {
// Working variables
        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];
// Computation
        for (let i = 0; i < 64; i++) {
            if (i < 16) {
                W[i] = M[offset + i] | 0;
            } else {
                let gamma0x = W[i - 15]
                let gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^
                    ((gamma0x << 14) | (gamma0x >>> 18)) ^
                    (gamma0x >>> 3);
                let gamma1x = W[i - 2];
                let gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^
                    ((gamma1x << 13) | (gamma1x >>> 19)) ^
                    (gamma1x >>> 10);
                W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
            }
            let ch = (e & f) ^ (~e & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
            let sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7) | (e >>> 25));
            let t1 = h + sigma1 + ch + K[i] + W[i];
            let t2 = sigma0 + maj;
            h = g;
            g = f;
            f = e;
            e = (d + t1) | 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) | 0;
        }
// Intermediate hash value
        H[0] = (H[0] + a) | 0;
        H[1] = (H[1] + b) | 0;
        H[2] = (H[2] + c) | 0;
        H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0;
        H[5] = (H[5] + f) | 0;
        H[6] = (H[6] + g) | 0;
        H[7] = (H[7] + h) | 0;
    };
    let bytesToWords = function (bytes) {
        let words = [];
        for (let i = 0, b = 0; i < bytes.length; i++, b += 8) {
            words[b >>> 5] |= bytes[i] << (24 - b % 32)
        }
        return words;
    };
    let wordsToBytes = function (words) {
        let bytes = [];
        for (let b = 0; b < words.length * 32; b += 8) {
            bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
        }
        return bytes;
    };

    let H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
    let m = bytesToWords(message);
    let l = message.length * 8;
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >> 9) << 4) + 15] = l;
    for (let i = 0; i < m.length; i += 16) {
        processBlock(H, m, i);
    }
    let digestbytes = wordsToBytes(H);
    return named_args.hex ? tools.bytesToHex(digestbytes): digestbytes;
}

function double_sha256(message, named_args) {
    if (named_args === undefined) named_args= {};
    if (named_args.hex === undefined) named_args.hex = false;
    return sha256(sha256(message, {hex: false}), named_args)
}


module.exports = {
    sha256,
    double_sha256
};