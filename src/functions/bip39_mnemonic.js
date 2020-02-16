module.exports = function (constants, tools) {
    let BN = tools.BN;
    let nodeCrypto = tools.nodeCrypto;
    let window = tools.window;
    let defArgs = tools.defArgs;

    function getRandomValues(buf) {
        if (window.crypto && window.crypto.getRandomValues) {
            return window.crypto.getRandomValues(buf);
        }
        if (typeof window.msCrypto === 'object' && typeof window.msCrypto.getRandomValues === 'function') {
            return window.msCrypto.getRandomValues(buf);
        }

        if (nodeCrypto!==false) {
            if (!(buf instanceof Uint8Array)) {
                throw new TypeError('expected Uint8Array');
            }
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
        } else {
            throw new Error('No secure random number generator available.');
        }
    }

    function lngamma(z) {
        if (z < 0) return NaN;
        let x = constants.GAMMA_TABLE_LN[0];
        for (let i = constants.GAMMA_TABLE_LN.length - 1; i > 0; --i) x += constants.GAMMA_TABLE_LN[i] / (z + i);
        let t = z + constants.GAMMA_NUM_LN + 0.5;
        return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x) - Math.log(z);
    }

    function igam(a, x) {
        if (x <= 0 || a <= 0)
            return 0.0;
        if (x > 1.0 && x > a)
            return 1.0 - igamc(a, x);
        let ans, ax, c, r;
        /* Compute xa exp(-x) / gamma(a) */
        ax = a * Math.log(x) - x - lngamma(a);
        if (ax < -constants.MAXLOG)
            return (0.0);
        ax = Math.exp(ax);
        /* power series */
        r = a;
        c = 1.0;
        ans = 1.0;

        do {
            r += 1.0;
            c *= x / r;
            ans += c;
        } while (c / ans > constants.MACHEP);

        return (ans * ax / a);
    }

    function igamc(a, x) {
        if (x <= 0 || a <= 0)
            return 1.0;

        if (x < 1.0 || x < a)
            return 1.0 - igam(a, x);
        let big = 4.503599627370496e15;
        let biginv = 2.22044604925031308085e-16;
        let ans, ax, c, yc, r, t, y, z;
        let pk, pkm1, pkm2, qk, qkm1, qkm2;
        ax = a * Math.log(x) - x - lngamma(a);
        if (ax < -constants.MAXLOG)
            return 0.0;

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
        } while (t > constants.MACHEP);

        return ans * ax;

    }

    function erfc(x) {
        let z = Math.abs(x);
        let t = 1 / (1 + z / 2);
        let r = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 +
            t * (0.37409196 + t * (0.09678418 + t * (-0.18628806 +
                t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 +
                    t * (-0.82215223 + t * 0.17087277)))))))));
        return x >= 0 ? r : 2 - r;
    }

    function randomness_test(b) {
        // NIST SP 800-22 randomness tests
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf

        let p = new BN(b);
        let s = p.toString(2).padStart(256, '0')
        // Frequency (Monobit) Test
        let n = s.length
        let s_0 = (s.match(/0/g) || []).length;
        let s_1 = (s.match(/1/g) || []).length;
        let s_obs = Math.abs(s_1 - s_0) / Math.sqrt(2 * n);
        if (!(erfc(s_obs) > 0.01)) throw new Error('Frequency (Monobit) Test failed.');

        // Runs Test
        let pi = s_1 / n;
        if (!(Math.abs(pi - 0.5) < 2 / Math.sqrt(n))) throw new Error('Runs Test failed.');
        let v = 1;
        for (let i = 0; i < n - 1; i++) v += (s[i] === s[i + 1]) ? 0 : 1;
        let a = v - 2 * n * pi * (1 - pi);
        let q = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
        if (!(erfc(Math.abs(a) / q) > 0.01)) throw new Error('Runs Test failed.');

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
            if (!(igamc(k / 2, x_sqrt / 2) > 0.01)) throw new Error('Test for the Longest Run of Ones in a Block failed.');
        }
    }

    return {
        generateEntropy: (A = {}) => {
            defArgs(A, {strength: 256, hex: true, sec256k1Order:true});
            if (!([128, 160, 192, 224, 256].includes(A.strength)))
                throw new TypeError('strength should be one of the following [128, 160, 192, 224, 256]');

            let b = new tools.Buffer.alloc(32);
            let attempt = 0;
            let order = new BN(constants.ECDSA_SEC256K1_ORDER, 16);
            let p;
            let found;
            do {
                found = true;
                attempt += 1;
                if (attempt > 100) throw new Error('Generate randomness failed');
                getRandomValues(b);

                if (A.sec256k1Order) {
                    p = new BN(b);
                    if ((p.gte(order))) continue;
                }

                try {
                    randomness_test(b);
                } catch (e) { found = false; }
            }
            while (!found);

            b = b.slice(0,A.strength / 8);
            return A.hex ? b.toString('hex') : b;
        },
        igam: igam,
        igamc: igamc
    }
};