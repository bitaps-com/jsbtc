module.exports = function (S) {
    let CM = S.__bitcoin_core_crypto.module;
    let malloc = CM._malloc;
    let free = CM._free;
    let BA = S.Buffer.alloc;
    let BC = S.Buffer.concat;
    let BF = S.Buffer.from;
    let ARGS = S.defArgs;
    let getBuffer = S.getBuffer;
    let BN = S.BN;
    let getValue = CM.getValue;

    S.createMasterXPrivateKey = (seed, A = {}) => {
        ARGS(A, {testnet: false, base58: true});
        let i = S.hmacSha512("Bitcoin seed", seed);
        let m = i.slice(0, 32);
        let c = i.slice(32);
        let mi = new BN(m);
        if ((mi.gte(S.ECDSA_SEC256K1_ORDER)||mi.lte(1))) return null;
        let key = (A.testnet) ? S.TESTNET_XPRIVATE_KEY_PREFIX : S.MAINNET_XPRIVATE_KEY_PREFIX;
        key = BC([key, BA(9,0), c, BA(1, 0), m])
        if (A.base58) return S.encodeBase58(BC([key, S.doubleSha256(key).slice(0,4)]));
        return key;
    };

    S.xPrivateToXPublicKey = (xKey, A = {}) => {
        ARGS(A, {base58: true});
        if (S.isString(xKey)) xKey = S.decodeBase58(xKey, {hex: false}).slice(0, -4);
        if (!S.isBuffer(xKey)) throw new Error("invalid xPrivateKey");
        if (xKey.length !== 78) throw new Error("invalid xPrivateKey");
        let prefix;
        if (xKey.slice(0, 4).equals(S.TESTNET_XPRIVATE_KEY_PREFIX)) prefix = S.TESTNET_XPUBLIC_KEY_PREFIX;
        else if (xKey.slice(0, 4).equals(S.MAINNET_XPRIVATE_KEY_PREFIX)) prefix = S.MAINNET_XPUBLIC_KEY_PREFIX;
        else throw new Error("invalid xPrivateKey");
        let key = BC([prefix, xKey.slice(4, 45),
                      S.privateToPublicKey(xKey.slice(46), {hex: false})]);
        if (A.base58) return S.encodeBase58(BC([key, S.doubleSha256(key).slice(0,4)]));
        return key;
    };

    S.__decodeParh = (p) => {
        p = p.split('/');
        if (p[0]!=='m')  throw new Error("invalid path");
        let r = [];
        for (let i = 1; i < p.length; i++) {
            let k = parseInt(p[i]);
            if ((p[i][p[i].length-1] ==="'") && (k < S.HARDENED_KEY)) k += S.HARDENED_KEY;
            r.push(k);
        }
        return r;
    };

    S.deriveXKey = (xKey, path, A = {}) => {
        ARGS(A, {base58: true});
        if (S.isString(xKey))  xKey = S.decodeBase58(xKey, {checkSum: true, hex:false});
        let prefix = xKey.slice(0,4);
        path = S.__decodeParh(path);
        if ((prefix.equals(S.MAINNET_XPRIVATE_KEY_PREFIX))||(prefix.equals(S.TESTNET_XPRIVATE_KEY_PREFIX)))
            for (let p of path) xKey = S.__deriveChildXPrivateKey(xKey, p);
        else if ((prefix.equals(S.MAINNET_XPUBLIC_KEY_PREFIX))||(prefix.equals(S.TESTNET_XPUBLIC_KEY_PREFIX)))
            for (let p of path) xKey = S.__deriveChildXPublicKey(xKey, p);
        else throw new Error("invalid extended key");
        if (A.base58) return S.encodeBase58(xKey, {checkSum: true});
        return xKey;
    };


    S.__deriveChildXPrivateKey = (xPrivateKey, i) => {
        let c = xPrivateKey.slice(13, 45);
        let k = xPrivateKey.slice(45);
        let depth = xPrivateKey[4] + 1;
        if (depth > 255) throw new Error("path depth should be <= 255");
        let pub = S.privateToPublicKey(k.slice(1), {hex: false});
        let fingerprint = S.hash160(pub).slice(0, 4);
        let s = S.hmacSha512(c, BC([(i >= S.HARDENED_KEY) ? k : pub, BF(S.intToBytes(i,4,"big"))]));
        let pi = new BN(s.slice(0, 32));
        if ((pi.gte(S.ECDSA_SEC256K1_ORDER))) return null;
        let ki = new BN(k.slice(1));
        ki = ki.add(pi);
        ki = ki.mod(S.ECDSA_SEC256K1_ORDER);
        if (ki.isZero()) return null;
        let key = ki.toArrayLike(S.Buffer,'be', 32);
        return BC([xPrivateKey.slice(0,4), BF([depth]), fingerprint, BF(S.intToBytes(i,4,"big")),
                   s.slice(32), BA(1,0), key]);
    };

    S.__deriveChildXPublicKey = (xPublicKey, i) => {
        let c = xPublicKey.slice(13, 45);
        let k = xPublicKey.slice(45);
        let depth = xPublicKey[4] + 1;
        if (depth > 255) throw new Error("path depth should be <= 255");
        if (i >= S.HARDENED_KEY) throw new Error("derivation from extended public key impossible");
        let fingerprint = S.hash160(k).slice(0, 4);
        let s = S.hmacSha512(c, BC([k, BF(S.intToBytes(i,4,"big"))]));
        let pi = new BN(s.slice(0, 32));
        if ((pi.gte(S.ECDSA_SEC256K1_ORDER))) return null;
        let pk = S.publicKeyAdd(k, s.slice(0,32), {hex: false});
        return BC([xPublicKey.slice(0,4), BF([depth]), fingerprint, BF(S.intToBytes(i,4,"big")), s.slice(32), pk]);
    };

    S.publicFromXPublicKey = (xPub, A = {}) => {
        ARGS(A, {hex: true});
        if (S.isString(xPub)) xPub = S.decodeBase58(xPub, {checkSum: true, hex: false});
        if (xPub.length !== 78) throw new Error("invalid extended public key");
        return (A.hex) ? xPub.slice(45).hex() : xPub.slice(45)
    };

    S.privateFromXPrivateKey = (xPriv, A = {}) => {
        ARGS(A, {wif: true});
        if (S.isString(xPriv)) xPriv = S.decodeBase58(xPriv, {checkSum: true, hex: false});
        if (xPriv.length !== 78) throw new Error("invalid extended public key");
        let prefix = xPriv.slice(0, 4);
        let testnet;
        if (prefix.equals(S.MAINNET_XPRIVATE_KEY_PREFIX)) testnet = false;
        else if  (prefix.equals(S.TESTNET_XPRIVATE_KEY_PREFIX)) testnet = true;
        else
            throw new Error("invalid extended public key");
        return (A.wif) ? S.privateKeyToWif(xPriv.slice(46), {testnet: testnet, wif:true}) : xPriv.slice(46)
    };

    S.isXPrivateKeyValid = (xPriv) => {
        if (S.isString(xPriv)) xPriv = S.decodeBase58(xPriv, {checkSum: true, hex: false});
        if (xPriv.length !== 78) return false;
        let prefix = xPriv.slice(0, 4);
        if (prefix.equals(S.MAINNET_XPRIVATE_KEY_PREFIX)) return true;
        if (prefix.equals(S.TESTNET_XPRIVATE_KEY_PREFIX)) return true;
        if (prefix.equals(S.MAINNET_M49_XPRIVATE_KEY_PREFIX)) return true;
        if (prefix.equals(S.TESTNET_M49_XPRIVATE_KEY_PREFIX)) return true;
        if (prefix.equals(S.MAINNET_M84_XPRIVATE_KEY_PREFIX)) return true;
        return prefix.equals(S.TESTNET_M84_XPRIVATE_KEY_PREFIX);
    };

    S.isXPublicKeyValid = (xPub) => {
        if (S.isString(xPub)) xPub = S.decodeBase58(xPub, {checkSum: true, hex: false});
        if (xPub.length !== 78) return false;
        let prefix = xPub.slice(0, 4);
        if (prefix.equals(S.MAINNET_XPUBLIC_KEY_PREFIX)) return true;
        if (prefix.equals(S.TESTNET_XPUBLIC_KEY_PREFIX)) return true;
        if (prefix.equals(S.MAINNET_M49_XPUBLIC_KEY_PREFIX)) return true;
        if (prefix.equals(S.TESTNET_M49_XPUBLIC_KEY_PREFIX)) return true;
        if (prefix.equals(S.MAINNET_M84_XPUBLIC_KEY_PREFIX)) return true;
        return prefix.equals(S.TESTNET_M84_XPUBLIC_KEY_PREFIX);
    };

    S.pathXKeyTo_BIP32_XKey = (xKey, A = {}) => {
        ARGS(A, {base58: true});
        if (S.isString(xKey)) xKey = S.decodeBase58(xKey, {checkSum: true, hex: false});
        if (xKey.length !== 78) throw new Error("invalid extended key");
        let prefix = xKey.slice(0, 4);
        let newPrefix;
        if (prefix.equals(S.MAINNET_XPUBLIC_KEY_PREFIX)) newPrefix = prefix;
        else if (prefix.equals(S.TESTNET_XPUBLIC_KEY_PREFIX)) newPrefix = prefix;
        else if (prefix.equals(S.MAINNET_XPRIVATE_KEY_PREFIX)) newPrefix = prefix;
        else if (prefix.equals(S.TESTNET_XPRIVATE_KEY_PREFIX)) newPrefix = prefix;
        else if (prefix.equals(S.MAINNET_M49_XPUBLIC_KEY_PREFIX)) newPrefix = S.MAINNET_XPUBLIC_KEY_PREFIX;
        else if (prefix.equals(S.MAINNET_M84_XPUBLIC_KEY_PREFIX)) newPrefix = S.MAINNET_XPUBLIC_KEY_PREFIX;
        else if (prefix.equals(S.TESTNET_M49_XPUBLIC_KEY_PREFIX)) newPrefix = S.TESTNET_XPUBLIC_KEY_PREFIX;
        else if (prefix.equals(S.TESTNET_M84_XPUBLIC_KEY_PREFIX)) newPrefix = S.TESTNET_XPUBLIC_KEY_PREFIX;
        else if (prefix.equals(S.MAINNET_M49_XPRIVATE_KEY_PREFIX)) newPrefix = S.MAINNET_XPRIVATE_KEY_PREFIX;
        else if (prefix.equals(S.TESTNET_M49_XPRIVATE_KEY_PREFIX)) newPrefix = S.TESTNET_XPRIVATE_KEY_PREFIX;
        else if (prefix.equals(S.TESTNET_M84_XPRIVATE_KEY_PREFIX)) newPrefix = S.TESTNET_XPRIVATE_KEY_PREFIX;
        else if (prefix.equals(S.MAINNET_M84_XPRIVATE_KEY_PREFIX)) newPrefix = S.MAINNET_XPRIVATE_KEY_PREFIX;
        else throw new Error("invalid extended key");
        if (A.base58) return S.encodeBase58(BC([newPrefix, xKey.slice(4)]), {checkSum: true});
        return BC([newPrefix, xKey.slice(4)]);
    };

    S.BIP32_XKeyToPathXKey = (xKey, pathType,  A = {}) => {
        ARGS(A, {base58: true});
        if (!["BIP44", "BIP49", "BIP84"].includes(pathType))
            throw new Error("unsupported path type " + pathType);
        if (S.isString(xKey)) xKey = S.decodeBase58(xKey, {checkSum: true, hex: false});
        if (xKey.length !== 78) throw new Error("invalid extended key");
        let prefix = xKey.slice(0, 4);
        let newPrefix;
        if (prefix.equals(S.TESTNET_XPRIVATE_KEY_PREFIX))
            switch (pathType) {
                case "BIP44": newPrefix = S.TESTNET_M44_XPRIVATE_KEY_PREFIX;
                break;
                case "BIP49": newPrefix = S.TESTNET_M49_XPRIVATE_KEY_PREFIX;
                break;
                case "BIP84": newPrefix = S.TESTNET_M84_XPRIVATE_KEY_PREFIX;
            }
        else if (prefix.equals(S.MAINNET_XPRIVATE_KEY_PREFIX))
            switch (pathType) {
                case "BIP44": newPrefix = S.MAINNET_M44_XPRIVATE_KEY_PREFIX;
                    break;
                case "BIP49": newPrefix = S.MAINNET_M49_XPRIVATE_KEY_PREFIX;
                    break;
                case "BIP84": newPrefix = S.MAINNET_M84_XPRIVATE_KEY_PREFIX;
            }
        else if (prefix.equals(S.TESTNET_XPUBLIC_KEY_PREFIX))
            switch (pathType) {
                case "BIP44": newPrefix = S.TESTNET_M44_XPUBLIC_KEY_PREFIX;
                    break;
                case "BIP49": newPrefix = S.TESTNET_M49_XPUBLIC_KEY_PREFIX;
                    break;
                case "BIP84": newPrefix = S.TESTNET_M84_XPUBLIC_KEY_PREFIX;
            }
        else if (prefix.equals(S.MAINNET_XPUBLIC_KEY_PREFIX))
            switch (pathType) {
                case "BIP44": newPrefix = S.MAINNET_M44_XPUBLIC_KEY_PREFIX;
                    break;
                case "BIP49": newPrefix = S.MAINNET_M49_XPUBLIC_KEY_PREFIX;
                    break;
                case "BIP84": newPrefix = S.MAINNET_M84_XPUBLIC_KEY_PREFIX;
            }
        else throw new Error("invalid extended key");
        if (A.base58) return S.encodeBase58(BC([newPrefix, xKey.slice(4)]), {checkSum: true});
        return BC([newPrefix, xKey.slice(4)]);
    };


};