module.exports = function (constants, crypto, tools, mnemonic, encoders, hash,
                           secp256k1PrecompContextSign, secp256k1PrecompContextVerify) {
    let Buffer = tools.Buffer;
    let isBuffer = tools.isBuffer;
    let malloc = crypto.module._malloc;
    let free = crypto.module._free;
    let getValue = crypto.module.getValue;

    return {
        createPrivateKey: function (named_args = {compressed: true, testnet: false, wif: true, hex: false}) {
            if (named_args.compressed === undefined) named_args.compressed = true;
            if (named_args.testnet === undefined) named_args.testnet = false;
            if (named_args.wif === undefined) named_args.wif = true;
            if (named_args.hex === undefined) named_args.hex = false;
            if (named_args.wif) return this.privateKeyToWif(mnemonic.generateEntropy({hex: false}), named_args);
            if (named_args.hex) return mnemonic.generateEntropy({hex: true});
            return mnemonic.generateEntropy({hex: false});
        },
        privateKeyToWif: function (h, named_args = {compressed: true, testnet: false}) {
            if (named_args.compressed === undefined) named_args.compressed = true;
            if (named_args.testnet === undefined) named_args.testnet = false;
            if (!isBuffer(h)) {
                if (tools.isString(h)) {
                    h = Buffer.from(h, 'hex');
                } else {
                    throw new Error('invalid byte string ');
                }
            }
            if (h.length !== 32) throw new Error('invalid byte string');
            let prefix;
            if (named_args.testnet) {
                prefix = Buffer.from(constants.TESTNET_PRIVATE_KEY_BYTE_PREFIX);
            } else {
                prefix = Buffer.from(constants.MAINNET_PRIVATE_KEY_BYTE_PREFIX);
            }

            if (named_args.compressed) h = Buffer.concat([prefix, h, Buffer.from([1])]);
            else h = Buffer.concat([prefix, h]);

            h = Buffer.concat([h, hash.doubleSha256(h).slice(0, 4)]);
            return (encoders.encodeBase58(h));
        },
        wifToPrivateKey: function (h, named_args = {hex: true}) {
            if (named_args.hex === undefined) named_args.hex = true;
            h = encoders.decodeBase58(h, {hex: false});
            if (!hash.doubleSha256(h.slice(0, h.length - 4), {hex: false}).slice(0, 4).equals(h.slice(h.length - 4, h.length)))
                throw new Error('invalid byte string');
            return (named_args.hex) ? h.slice(1, 33).toString('hex') : h.slice(1, 33)
        },
        isWifValid: function (wif) {
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
            } catch (e) {
            }

            return false;
        },
        privateToPublicKey: function (privateKey, named_args = {compressed: true, hex: true}) {
            if (named_args.compressed === undefined) named_args.compressed = true;
            if (named_args.hex === undefined) named_args.hex = true;

            if (!isBuffer(privateKey)) {
                if (tools.isString(privateKey)) {
                    if (tools.isHex(privateKey)) privateKey = Buffer.from(privateKey, 'hex');
                    else {
                        let unc = [constants.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                            constants.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX];
                        if  (unc.includes(privateKey[0])) named_args.compressed = false;
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
            let pubLen = (named_args.compressed) ? 33 : 65;
            let publicKeySerializedPointer = malloc(pubLen);
            let pubLenPointer = malloc(1);
            crypto.module.HEAPU8.set([pubLen], pubLenPointer);
            let flag = (named_args.compressed) ? constants.SECP256K1_EC_COMPRESSED : constants.SECP256K1_EC_UNCOMPRESSED;
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
            return (named_args.hex)? out.toString('hex'): out;
        },
        isPublicKeyValid: function (key) {
            if (tools.isString(key))
                try {
                key = Buffer.from(key, 'hex');
                } catch (e) {return false; }
            if (key.length < 33) return false;
            if ((key[0] === 4)&&(key.length !== 65)) return false;
            if ((key[0] === 2)||(key[0] === 3))
                if (key.length !== 33) return false;
            return true;
        }
    }
};
