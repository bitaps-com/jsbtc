module.exports = function (S) {
    let Buffer = S.Buffer;
    let BF = Buffer.from;
    let BC = Buffer.concat;
    let BA = Buffer.alloc;
    let isBuffer = S.isBuffer;
    let getBuffer = S.getBuffer;
    let ARGS = S.defArgs;
    let crypto = S.__bitcoin_core_crypto.module;
    let malloc = crypto._malloc;
    let free = crypto._free;
    let getValue = crypto.getValue;


    S.createPrivateKey = (A = {}) => {
        ARGS(A, {compressed: true, testnet: false, wif: true, hex: false});
        if (A.wif) return S.privateKeyToWif(S.generateEntropy({hex: false}), A);
        if (A.hex) return S.generateEntropy({hex: true});
        return S.generateEntropy({hex: false});
    };

    S.privateKeyToWif = (h, A = {}) => {
        ARGS(A, {compressed: true, testnet: false});
        h = getBuffer(h);
        if (h.length !== 32) throw new Error('invalid byte string');
        let prefix;
        if (A.testnet) prefix = BF(S.TESTNET_PRIVATE_KEY_BYTE_PREFIX);
        else prefix = BF(S.MAINNET_PRIVATE_KEY_BYTE_PREFIX);

        if (A.compressed) h = BC([prefix, h, Buffer.from([1])]);
        else h = BC([prefix, h]);

        h = BC([h, S.doubleSha256(h).slice(0, 4)]);
        return S.encodeBase58(h);
    };

    S.wifToPrivateKey = (h, A = {}) => {
        ARGS(A, {hex: true});
        h = S.decodeBase58(h, {hex: false});
        if (!S.doubleSha256(h.slice(0, h.length - 4), {hex: false}).slice(0, 4).equals(h.slice(h.length - 4, h.length)))
            throw new Error('invalid byte string');
        return (A.hex) ? h.slice(1, 33).hex() : h.slice(1, 33)
    };

    S.isWifValid = (wif) => {
        if (!S.isString(wif)) return false;
        if (!S.PRIVATE_KEY_PREFIX_LIST.includes(wif[0])) return false;
        try {
            let h = S.decodeBase58(wif, {hex: false});
            let checksum = h.slice(h.length - 4, h.length);
            let unc = [S.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                S.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX];
            if (unc.includes(wif[0])) {
                if (h.length !== 37) return false;
            } else {
                if (h.length !== 38) return false;
            }
            let calcChecksum = S.doubleSha256(h.slice(0, h.length - 4), {hex: false}).slice(0, 4);
            return calcChecksum.equals(checksum);
        } catch (e) {
        }
        return false;
    };

    S.privateToPublicKey = (privateKey, A = {}) => {
        ARGS(A, {compressed: true, hex: true});
        if (!isBuffer(privateKey)) {
            if (S.isString(privateKey)) {
                if (S.isHex(privateKey)) privateKey = Buffer.from(privateKey, 'hex');
                else {
                    let unc = [S.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                        S.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX];
                    if (unc.includes(privateKey[0])) A.compressed = false;
                    privateKey = S.wifToPrivateKey(privateKey, {hex: false})
                }
            } else {
                throw new Error('invalid private key string');
            }
        }
        if (privateKey.length !== 32) throw new Error('private key length invalid');
        let privateKeyPointer = malloc(32);
        let publicKeyPointer = malloc(64);
        crypto.HEAPU8.set(privateKey, privateKeyPointer);
        crypto._secp256k1_ec_pubkey_create(S.secp256k1PrecompContextSign, publicKeyPointer, privateKeyPointer);
        let outq = new BA(64);
        for (let i = 0; i < 64; i++) outq[i] = getValue(publicKeyPointer + i, 'i8');
        let pubLen = (A.compressed) ? 33 : 65;
        let publicKeySerializedPointer = malloc(65);
        let pubLenPointer = malloc(1);
        crypto.HEAPU8.set([pubLen], pubLenPointer);
        let flag = (A.compressed) ? S.SECP256K1_EC_COMPRESSED : S.SECP256K1_EC_UNCOMPRESSED;
        let r = crypto._secp256k1_ec_pubkey_serialize(S.secp256k1PrecompContextVerify,
            publicKeySerializedPointer, pubLenPointer, publicKeyPointer, flag);
        let out;
        if (r) {
            out = new BA(pubLen);
            for (let i = 0; i < pubLen; i++) out[i] = getValue(publicKeySerializedPointer + i, 'i8');
        } else out = false;
        free(privateKeyPointer);
        free(publicKeyPointer);
        free(pubLenPointer);
        free(publicKeySerializedPointer);
        if (out === false) throw new Error('privateToPublicKey failed');
        return (A.hex) ? out.hex() : out;
    };

    S.isPublicKeyValid = (key) => {
        if (S.isString(key)) {
            if (!S.isHex(key)) return false;
            key = BF(key, 'hex');
        }
        if (key.length < 33) return false;
        if ((key[0] === 4) && (key.length !== 65)) return false;
        if ((key[0] === 2) || (key[0] === 3))
            if (key.length !== 33) return false;
        return !((key[0] < 2) || (key[0] > 4));
    }

};
