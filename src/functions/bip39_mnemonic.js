var BN = require('bn.js');
var window = require('global/window');
var nodeCrypto = require('crypto');
var constants = require('../constants.js');
var tools = require('./tools.js');

function getRandomValues(buf) {
    if (window.crypto && window.crypto.getRandomValues) {
        return window.crypto.getRandomValues(buf);
    }
    if (typeof window.msCrypto === 'object' && typeof window.msCrypto.getRandomValues === 'function') {
        return window.msCrypto.getRandomValues(buf);
    }
    if (nodeCrypto.randomBytes) {
        if (!(buf instanceof Uint8Array)) {
            throw new TypeError('expected Uint8Array');
        }
        if (buf.length > 65536) {
            var e = new Error();
            e.code = 22;
            e.message = 'Failed to execute \'getRandomValues\' on \'Crypto\': The ' +
                'ArrayBufferView\'s byte length (' + buf.length + ') exceeds the ' +
                'number of bytes of entropy available via this API (65536).';
            e.name = 'QuotaExceededError';
            throw e;
        }
        var bytes = nodeCrypto.randomBytes(buf.length);
        buf.set(bytes);
        return buf;
    }
    else {
        throw new Error('No secure random number generator available.');
    }
}


const GAMMA_NUM_LN = 607 / 128;

const GAMMA_TABLE_LN = [0.99999999999999709182,
    57.156235665862923517,
    -59.597960355475491248,
    14.136097974741747174,
    -0.49191381609762019978,
    0.33994649984811888699e-4,
    0.46523628927048575665e-4,
    -0.98374475304879564677e-4,
    0.15808870322491248884e-3,
    -0.21026444172410488319e-3,
    0.21743961811521264320e-3,
    -0.16431810653676389022e-3,
    0.84418223983852743293e-4,
    -0.26190838401581408670e-4,
    0.36899182659531622704e-5
];
const MACHEP = 1.11022302462515654042E-16;
const MAXLOG = 7.09782712893383996732E2;


function lngamma(z) {
    if (z < 0) return NaN;
    let x = GAMMA_TABLE_LN[0];
    for (let i = GAMMA_TABLE_LN.length - 1; i > 0; --i) x += GAMMA_TABLE_LN[i] / (z + i);
    let t = z + GAMMA_NUM_LN + 0.5;
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
    if (ax < -MAXLOG)
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
    } while (c / ans > MACHEP);

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
    if (ax < -MAXLOG)
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
        }
        else t = 1.0;

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
    } while (t > MACHEP);

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

function randomness_test(s) {
    // Frequency (Monobit) Test
    let n = s.length
    let s_0 = (s.match(/0/g) || []).length;
    let s_1 = (s.match(/1/g) || []).length;
    let s_obs = Math.abs(s_1 - s_0) / Math.sqrt(2 * n);
    if (!(erfc(s_obs) > 0.01)) return false;

    // Runs Test
    let pi = s_1 / n;
    if (!(Math.abs(pi - 0.5) < 2 / Math.sqrt(n))) return false;
    let v = 1;
    for (let i = 0; i < n - 1; i++) v += (s[i] === s[i + 1]) ? 0 : 1;
    let a = v - 2 * n * pi * (1 - pi);
    let q = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
    if (!(erfc(Math.abs(a) / q) > 0.01)) return false;

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
        if (!(igamc(k / 2, x_sqrt / 2) > 0.01)) return false;
    }
    return true;
}

function generate_entropy(named_args) {
    if (named_args === undefined) named_args = {};
    if (named_args.strength === undefined) named_args.strength = 256;
    if (named_args.hex === undefined) named_args.hex = true;
    if (!([128, 160, 192, 224, 256].includes(named_args.strength))) {
        throw new TypeError('strength should be one of the following [128, 160, 192, 224, 256]');
    }
    let b = new Uint8Array(named_args.strength / 8);
    let attempt = 0;
    let p, t;
    do {
        attempt += 1;
        if (attempt > 100) throw new Error('Generate randomness failed');
        getRandomValues(b);
        p = new BN(b);
        if ((p.gte(constants.ECDSA_SEC256K1_ORDER))) continue;
        t = randomness_test(p.toString(2).padStart(256, '0'));
    }
    while (!t);
    let a = p.toArray().slice(0, parseInt(named_args.strength / 8));
    return named_args.hex ? tools.bytesToHex(a): a;
}



module.exports = {
    generate_entropy,
    igam,
    igamc
};
