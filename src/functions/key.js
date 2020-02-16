module.exports = function (constants, crypto, tools, mnemonic, encoders, hash,
                           secp256k1PrecompContextSign, secp256k1PrecompContextVerify) {
    let Buffer = tools.Buffer;
    let isBuffer = tools.isBuffer;
    let getBuffer = tools.getBuffer;
    let defArgs = tools.defArgs;
    let malloc = crypto.module._malloc;
    let free = crypto.module._free;
    let getValue = crypto.module.getValue;

    return {
        createPrivateKey: function (A = {}) {
            defArgs(A, {compressed: true, testnet: false, wif: true, hex: false});
            if (A.wif) return this.privateKeyToWif(mnemonic.generateEntropy({hex: false}), A);
            if (A.hex) return mnemonic.generateEntropy({hex: true});
            return mnemonic.generateEntropy({hex: false});
        },
        privateKeyToWif: (h, A = {compressed: true, testnet: false}) => {
            defArgs(A, {compressed: true, testnet: false});
            h = getBuffer(h);
            if (h.length !== 32) throw new Error('invalid byte string');
            let prefix;
            if (A.testnet) prefix = Buffer.from(constants.TESTNET_PRIVATE_KEY_BYTE_PREFIX);
            else prefix = Buffer.from(constants.MAINNET_PRIVATE_KEY_BYTE_PREFIX);

            if (A.compressed) h = Buffer.concat([prefix, h, Buffer.from([1])]);
            else h = Buffer.concat([prefix, h]);

            h = Buffer.concat([h, hash.doubleSha256(h).slice(0, 4)]);
            return encoders.encodeBase58(h);
        },
        wifToPrivateKey: (h, A = {}) => {
            defArgs(A, {hex: true});
            h = encoders.decodeBase58(h, {hex: false});
            if (!hash.doubleSha256(h.slice(0, h.length - 4), {hex: false}).slice(0, 4).equals(h.slice(h.length - 4, h.length)))
                throw new Error('invalid byte string');
            return (A.hex) ? h.slice(1, 33).toString('hex') : h.slice(1, 33)
        },
        isWifValid: (wif) => {
            if (!tools.isString(wif)) return false;
            if (!constants.PRIVATE_KEY_PREFIX_LIST.includes(wif[0])) return false;
            try {
                let h = encoders.decodeBase58(wif, {hex: false});
                let checksum = h.slice(h.length - 4, h.length);
                let unc = [constants.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                    constants.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX];
                if (unc.includes(wif[0])) {
                    if (h.length !== 37) return false;
                } else {
                    if (h.length !== 38) return false;
                }
                let calcChecksum = hash.doubleSha256(h.slice(0, h.length - 4), {hex: false}).slice(0, 4);
                return calcChecksum.equals(checksum);
            } catch (e) {}
            return false;
        },
        privateToPublicKey: function (privateKey, A = {}) {
            defArgs(A, {compressed: true, hex: true});
            if (!isBuffer(privateKey)) {
                if (tools.isString(privateKey)) {
                    if (tools.isHex(privateKey)) privateKey = Buffer.from(privateKey, 'hex');
                    else {
                        let unc = [constants.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                            constants.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX];
                        if  (unc.includes(privateKey[0])) A.compressed = false;
                        privateKey = this.wifToPrivateKey(privateKey, {hex: false})
                    }
                } else {
                    throw new Error('invalid private key string');
                }
            }
            if (privateKey.length !== 32) throw new Error('private key length invalid');
            let privateKeyPointer = malloc(32);
            let publicKeyPointer = malloc(64);
            crypto.module.HEAPU8.set(privateKey, privateKeyPointer);
            crypto.module._secp256k1_ec_pubkey_create(secp256k1PrecompContextSign, publicKeyPointer, privateKeyPointer);
            let pubLen = (A.compressed) ? 33 : 65;
            let publicKeySerializedPointer = malloc(pubLen);
            let pubLenPointer = malloc(1);
            crypto.module.HEAPU8.set([pubLen], pubLenPointer);
            let flag = (A.compressed) ? constants.SECP256K1_EC_COMPRESSED : constants.SECP256K1_EC_UNCOMPRESSED;
            let r = crypto.module._secp256k1_ec_pubkey_serialize(secp256k1PrecompContextSign,
                publicKeySerializedPointer, pubLenPointer, publicKeyPointer, flag);
            let out;
            if (r) {
                out = new Buffer.alloc(pubLen);
                for (let i=0; i<pubLen; i++) out[i] = getValue(publicKeySerializedPointer + i, 'i8');
            } else out = false;
            free(privateKeyPointer);
            free(publicKeyPointer);
            free(pubLenPointer);
            free(publicKeySerializedPointer);
            if (out === false) throw new Error('privateToPublicKey failed');
            return (A.hex)? out.toString('hex'): out;
        },
        isPublicKeyValid: function (key) {
            if (tools.isString(key)) {
                if (!tools.isHex(key)) return false;
                key = Buffer.from(key, 'hex');
            }
            if (key.length < 33) return false;
            if ((key[0] === 4)&&(key.length !== 65)) return false;
            if ((key[0] === 2)||(key[0] === 3))
                if (key.length !== 33) return false;
            return !((key[0] < 2) || (key[0] > 4));
        }
    }
};
