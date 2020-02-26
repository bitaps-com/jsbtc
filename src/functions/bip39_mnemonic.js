module.exports = function (S) {
    let BN = S.BN;
    let nodeCrypto = S.__nodeCrypto;
    let window = S.getWindow();
    let ARGS = S.defArgs;


    S.getRandomValues = (buf) => {
        if (window.crypto && window.crypto.getRandomValues) return window.crypto.getRandomValues(buf);

        if (typeof window.msCrypto === 'object' && typeof window.msCrypto.getRandomValues === 'function')
            return window.msCrypto.getRandomValues(buf);

        if (nodeCrypto!==false) {
            if (!(buf instanceof Uint8Array))  throw new TypeError('expected Uint8Array');
            if (buf.length > 65536) {
                let e = new Error();
                e.code = 22;
                e.message = 'Failed to execute \'getRandomValues\' on \'Crypto\': The ' +
                    'ArrayBufferView\'s byte length (' + buf.length + ') exceeds the ' +
                    'number of bytes of entropy available via this API (65536).';
                e.name = 'QuotaExceededError';
                throw e;
            }
            let bytes = nodeCrypto.randomBytes(buf.length);
            buf.set(bytes);
            return buf;
        } else throw new Error('No secure random number generator available.');
    };

    S.lngamma = (z) => {
        if (z < 0) return null;
        let x = S.GAMMA_TABLE_LN[0];
        for (let i = S.GAMMA_TABLE_LN.length - 1; i > 0; --i) x += S.GAMMA_TABLE_LN[i] / (z + i);
        let t = z + S.GAMMA_NUM_LN + 0.5;
        return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x) - Math.log(z);
    };

    S.igam = (a, x) => {
        if (x <= 0 || a <= 0) return 0.0;
        if (x > 1.0 && x > a) return 1.0 - S.igamc(a, x);
        let ans, ax, c, r;
        /* Compute xa exp(-x) / gamma(a) */
        ax = a * Math.log(x) - x - S.lngamma(a);
        if (ax < -S.MAXLOG) return (0.0);
        ax = Math.exp(ax);
        /* power series */
        r = a;
        c = 1.0;
        ans = 1.0;

        do {
            r += 1.0;
            c *= x / r;
            ans += c;
        } while (c / ans > S.MACHEP);

        return (ans * ax / a);
    };

    S.igamc = (a, x) => {
        if (x <= 0 || a <= 0) return 1.0;
        if (x < 1.0 || x < a) return 1.0 - igam(a, x);
        let big = 4.503599627370496e15;
        let biginv = 2.22044604925031308085e-16;
        let ans, ax, c, yc, r, t, y, z;
        let pk, pkm1, pkm2, qk, qkm1, qkm2;
        ax = a * Math.log(x) - x - S.lngamma(a);
        if (ax < -S.MAXLOG) return 0.0;
        ax = Math.exp(ax);
        y = 1.0 - a;
        z = x + y + 1.0;
        c = 0.0;
        pkm2 = 1.0;
        qkm2 = x;
        pkm1 = x + 1.0;
        qkm1 = z * x;
        ans = pkm1 / qkm1;

        do {
            c += 1.0;
            y += 1.0;
            z += 2.0;
            yc = y * c;
            pk = pkm1 * z - pkm2 * yc;
            qk = qkm1 * z - qkm2 * yc;
            if (qk !== 0) {
                r = pk / qk;
                t = Math.abs((ans - r) / r);
                ans = r;
            } else t = 1.0;

            pkm2 = pkm1;
            pkm1 = pk;
            qkm2 = qkm1;
            qkm1 = qk;
            if (Math.abs(pk) > big) {
                pkm2 *= biginv;
                pkm1 *= biginv;
                qkm2 *= biginv;
                qkm1 *= biginv;
            }
        } while (t > S.MACHEP);

        return ans * ax;
    };

    S.erfc = (x) => {
        let z = Math.abs(x);
        let t = 1 / (1 + z / 2);
        let r = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 +
            t * (0.37409196 + t * (0.09678418 + t * (-0.18628806 +
                t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 +
                    t * (-0.82215223 + t * 0.17087277)))))))));
        return x >= 0 ? r : 2 - r;
    };

    S.randomnessTest = (b) => {
        // NIST SP 800-22 randomness tests
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf

        let p = new BN(b);
        let s = p.toString(2).padStart(256, '0')
        // Frequency (Monobit) Test
        let n = s.length
        let s_0 = (s.match(/0/g) || []).length;
        let s_1 = (s.match(/1/g) || []).length;
        let s_obs = Math.abs(s_1 - s_0) / Math.sqrt(2 * n);
        if (!(S.erfc(s_obs) > 0.01)) throw new Error('Frequency (Monobit) Test failed.');

        // Runs Test
        let pi = s_1 / n;
        if (!(Math.abs(pi - 0.5) < 2 / Math.sqrt(n))) throw new Error('Runs Test failed.');
        let v = 1;
        for (let i = 0; i < n - 1; i++) v += (s[i] === s[i + 1]) ? 0 : 1;
        let a = v - 2 * n * pi * (1 - pi);
        let q = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
        if (!(S.erfc(Math.abs(a) / q) > 0.01)) throw new Error('Runs Test failed.');

        // Test for the Longest Run of Ones in a Block
        s = [s.substring(0, 128).match(/.{1,8}/g), s.substring(128, 256).match(/.{1,8}/g)];
        for (let w = 0; w < 2; w++) {
            let sl = s[w];
            v = [0, 0, 0, 0];
            for (let i = 0; i < sl.length; i++) {
                let q = sl[i].split('0');
                let l = q.reduce(function (a, b) {
                    return a.length > b.length ? a : b;
                }).length;
                switch (l) {
                    case 0:
                        v[0] += 1;
                        break;
                    case 1:
                        v[0] += 1;
                        break;
                    case 2:
                        v[1] += 1;
                        break;
                    case 3:
                        v[2] += 1;
                        break;
                    default:
                        v[3] += 1;
                }
            }

            let k = 3;
            let r = 16;
            pi = [0.2148, 0.3672, 0.2305, 0.1875];
            let x_sqrt = Math.pow(v[0] - r * pi[0], 2) / (r * pi[0]);
            x_sqrt += Math.pow(v[1] - r * pi[1], 2) / (r * pi[1]);
            x_sqrt += Math.pow(v[2] - r * pi[2], 2) / (r * pi[2]);
            x_sqrt += Math.pow(v[3] - r * pi[3], 2) / (r * pi[3]);
            if (!(S.igamc(k / 2, x_sqrt / 2) > 0.01))
                throw new Error('Test for the Longest Run of Ones in a Block failed.');
        }
    };


    S.generateEntropy = (A = {}) => {
            ARGS(A, {strength: 256, hex: true, sec256k1Order:true});
            if (!([128, 160, 192, 224, 256].includes(A.strength)))
                throw new TypeError('strength should be one of the following [128, 160, 192, 224, 256]');

            let b = S.Buffer.alloc(32);
            let attempt = 0;
            let order = new BN(S.ECDSA_SEC256K1_ORDER, 16);
            let p;
            let found;
            do {
                found = true;
                attempt++;
                if (attempt > 100) throw new Error('Generate randomness failed');
                S.getRandomValues(b);

                if (A.sec256k1Order) {
                    p = new BN(b);
                    if ((p.gte(order))) continue;
                }

                try {
                    S.randomnessTest(b);
                } catch (e) { found = false; }
            }
            while (!found);

            b = b.slice(0,A.strength / 8);
            return A.hex ? b.hex() : b;
        };

    S.entropyToMnemonic =  (e, A = {}) => {
        ARGS(A, {wordList: S.BIP39_WORDLIST});
        e = S.getBuffer(e);
        let i = new BN(e, 16);
        if (!([16, 20, 24, 28, 32].includes(e.length)))
            throw new TypeError('entropy length should be one of the following: [16, 20, 24, 28, 32]');
        if (!(A.wordList instanceof Array) || (A.wordList.length !== 2048))
            throw new TypeError('invalid wordlist');

        let b = Math.ceil(e.length * 8 / 32);
        i = i.shln(b).or(new BN(S.sha256(e)[0] >> (8-b)));
        let r = [];
        for (let d = (e.length * 8 + 8) / 11 | 0; d > 0; d--)
            r.push(A.wordList[i.shrn((d - 1) * 11).and(new BN(2047)).toNumber()]);
        return r.join(' ');
    };

    S.mnemonicToEntropy =  (m, A = {}) => {
        ARGS(A, {wordList: S.BIP39_WORDLIST, checkSum: false, hex: true});
        m = m.trim().split(/\s+/);
        if (!(S.isMnemonicValid(m, A))) throw new TypeError('invalid mnemonic words');
        let e = new BN(0);
        for (let w of m)  e = e.shln(11).or(new BN(A.wordList.indexOf(w)));
        let bitSize = m.length * 11;
        let checkSumBitLen = bitSize % 32;
        e = e.shrn(checkSumBitLen);
        e = e.toArrayLike(S.Buffer, 'be', Math.ceil((bitSize- checkSumBitLen)/8));
        return (A.hex) ? e.hex() : e;
    };

    S.isMnemonicValid =  (m, A = {}) => {
        ARGS(A, {wordList: S.BIP39_WORDLIST});
        if (S.isString(m)) m = m.trim().split(/\s+/);
        for (let w of m) if (!(A.wordList.includes(w))) return false;
        return true
    };

    S.isMnemonicCheckSumValid =  (m, A = {}) => {
        ARGS(A, {wordList: S.BIP39_WORDLIST});
        let e;
        try {
            e = S.mnemonicToEntropy(m, {wordList: A.wordList, hex: false});
        } catch (e) {
            return false;
        }
        m = m.trim().split(/\s+/);
        let bitSize = m.length * 11;
        let checkSumBitLen = bitSize % 32;
        let c = S.sha256(e)[0] >> (8 - checkSumBitLen);
        let c2 = S.intToBytes(A.wordList.indexOf(m.pop()), 1) & (2 ** checkSumBitLen - 1);
        return c === c2;
    };

    S.__combinations = (a, n) => {
        let results = [], result, mask, i;
        let total = Math.pow(2, a.length);
        for (let m = n; m < total; m++) {
            let r = [];
            i = a.length - 1;

            do {
                if ((m & (1 << i)) !== 0) r.push(a[i]);
            } while (i--);

            if (r.length >= n) {
                results.push(r);
            }
        }
        return results;
    };

    S.splitMnemonic = (threshold, total, m,  A = {}) => {
        ARGS(A, {wordList: S.BIP39_WORDLIST, checkSum: false, hex: true});
        let e =  S.mnemonicToEntropy(m, {wordList: A.wordList,
            checkSum: A.checkSum, hex: false});
        let shares = S.__split_secret(threshold, total, e);

        // shares validation
        let a = [];
        for (let i in shares) {
            i = parseInt(i);
            a.push([i, shares[i]])
        }
        let combinations = S.__combinations(a, threshold);
        for (let c of combinations) {
            let d = {};
            for (let q of c) d[q[0]] = q[1];
            let s = S.__restore_secret(d);
            if (!s.equals(e))  {
                throw new Error("split secret failed");
            }
        }

        let result = {};
        for (let i in shares) result[i] = S.entropyToMnemonic(shares[i], A);
        return result;
    };

    S.combineMnemonic = (shares, A = {}) =>  {
        let s = {};
        for (let i in shares) s[i] = S.mnemonicToEntropy(shares[i],
            {wordList: A.wordList,
                checkSum: A.checkSum, hex: false});
        return S.entropyToMnemonic(S.__restore_secret(s), A);
    }

};