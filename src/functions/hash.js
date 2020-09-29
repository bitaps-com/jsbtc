module.exports = function (S) {
    let CM = S.__bitcoin_core_crypto.module;
    let malloc = CM._malloc;
    let free = CM._free;
    let BA = S.Buffer.alloc;
    let ARGS = S.defArgs;
    let getBuffer = S.getBuffer;
    let BN = S.BN;
    let getValue = CM.getValue;

    S.sha256 = (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', hex: false});
        m = getBuffer(m, A.encoding);
        let bP = malloc(m.length);
        let oP = malloc(32);
        CM.HEAPU8.set(m, bP);
        CM._single_sha256(bP, m.length, oP);
        let out = new BA(32);
        for (let i = 0; i < 32; i++) out[i] = getValue(oP + i, 'i8');
        free(bP);
        free(oP);
        return (A.hex) ? out.hex() : out;
    };

    S.SHA256 = class {
        constructor () {
            this.ptr = new  CM.CSHA256();
            this.result = new BA(32);
            return this;
        };
        update(m, A = {}) {
            ARGS(A, {encoding: 'hex|utf8'});
            m = getBuffer(m, A.encoding);
            let bP = malloc(m.length);
            CM.HEAPU8.set(m, bP);
            this.ptr.Write(bP, m.length);
            free(bP);
            return this;
        };
        digest() {
            let oP = malloc(32);
            this.ptr.Finalize(oP);
            for (let i = 0; i < 32; i++) this.result[i] = getValue(oP + i, 'i8');
            free(oP);
            return this.result;
        };
        hexdigest() {
            let oP = malloc(32);
            this.ptr.Finalize(oP);
            for (let i = 0; i < 32; i++) this.result[i] = getValue(oP + i, 'i8');
            free(oP);
            return this.result.hex();
        }
    };

    S.doubleSha256 = (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', hex: false});
        m = getBuffer(m, A.encoding);
        let bP = malloc(m.length);
        let oP = malloc(32);
        CM.HEAPU8.set(m, bP);
        CM._double_sha256(bP, m.length, oP);
        let out = new BA(32);
        for (let i = 0; i < 32; i++) out[i] = getValue(oP + i, 'i8');
        free(bP);
        free(oP);
        return (A.hex) ? out.hex() : out;
    };

    S.siphash =  (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', v0: S.BNZerro, v1: S.BNZerro});
        if (!(A.v1 instanceof BN) || !(A.v0 instanceof BN)) throw new Error('siphash init vectors v0, v1 must be BN instance');
        m = getBuffer(m, A.encoding);
        let v0b = A.v0.toArrayLike(Uint8Array, 'le', 8);
        let v1b = A.v1.toArrayLike(Uint8Array, 'le', 8);
        let bP = malloc(m.length);
        let v0Pointer = malloc(8);
        let v1Pointer = malloc(8);
        let oP = malloc(8);
        CM.HEAPU8.set(m, bP);
        CM.HEAPU8.set(v0b, v0Pointer);
        CM.HEAPU8.set(v1b, v1Pointer);
        CM._siphash(v0Pointer, v1Pointer, bP, m.length, oP);
        let out = new BA(9);
        for (let i = 0; i < 8; i++) out[8 - i] = getValue(oP + i, 'i8');
        free(bP);
        free(oP);
        return new BN(out);
    };

    S.ripemd160 = (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', hex: false});
        m = getBuffer(m, A.encoding);
        let bP = malloc(m.length);
        let oP = malloc(32);
        CM.HEAPU8.set(m, bP);
        CM.__ripemd160(bP, m.length, oP);
        let out = new BA(20);
        for (let i = 0; i < 20; i++) out[i] = getValue(oP + i, 'i8');
        free(bP);
        free(oP);
        return (A.hex) ? out.hex() : out;
    };

    S.md5 = (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', hex: false});
        m = getBuffer(m, A.encoding);
        let bP = malloc(m.length);
        let oP = malloc(16);
        CM.HEAPU8.set(m, bP);
        CM._md5sum(bP, m.length, oP);
        let out = new BA(16);
        for (let i = 0; i < 16; i++) out[i] = getValue(oP + i, 'i8');
        free(bP);
        free(oP);
        return (A.hex) ? out.hex() : out;
    };

    S.hash160 = (m, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', hex: false});
        return S.ripemd160(S.sha256(m, {hex: false, encoding: A.encoding}), {hex: A.hex});
    };

    S.hmacSha512 = (k, d, A = {}) => {
        ARGS(A, {encoding: 'hex|utf8', hex: false});
        k = getBuffer(k, A.encoding);
        d = getBuffer(d, A.encoding);
        let kP = malloc(k.length);
        let dP = malloc(d.length);
        let oP = malloc(64);
        CM.HEAPU8.set(k, kP);
        CM.HEAPU8.set(d, dP);
        CM._hmac_sha512_oneline(kP, k.length, dP, d.length, oP);
        let out = new BA(64);
        for (let i = 0; i < 64; i++) out[i] = getValue(oP + i, 'i8');
        free(kP);
        free(dP);
        free(oP);
        return (A.hex) ? out.hex() : out;
    };

    S.pbdkdf2HmacSha512 = (password, salt, i, A = {}) => {
        ARGS(A, {encoding: 'utf8', hex: false});
        let p = getBuffer(password, A.encoding);
        let s = getBuffer(salt, A.encoding);
        let pP = malloc(p.length);
        let sP = malloc(s.length);
        let oP = malloc(64);
        CM.HEAPU8.set(p, pP);
        CM.HEAPU8.set(s, sP);
        CM._pbkdf2_hmac_sha512(pP, p.length, sP, s.length, i,  oP, 64);
        let out = new BA(64);
        for (let i = 0; i < 64; i++) out[i] = getValue(oP + i, 'i8');
        free(pP);
        free(sP);
        free(oP);
        return (A.hex) ? out.hex() : out;
    };


};