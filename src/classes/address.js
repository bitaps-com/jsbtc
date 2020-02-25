module.exports = function (S) {
    let Buffer = S.Buffer;
    let defArgs = S.defArgs;
    let getBuffer = S.getBuffer;
    let BF = Buffer.from;
    let BC = Buffer.concat;
    let O = S.OPCODE;

    class PrivateKey {
        constructor(k, A = {}) {
            defArgs(A, {compressed: true, testnet: false});
            if (k === undefined) {
                this.compressed = A.compressed;
                this.testnet = A.testnet;
                this.key = S.createPrivateKey({wif: false});
                this.hex = this.key.hex();
                this.wif = S.privateKeyToWif(this.key, A);
            } else {
                if (S.isString(k)) {
                    if (S.isHex(k)) {
                        this.key = BF(k, 'hex');
                        this.compressed = A.compressed;
                        this.testnet = A.testnet;
                        this.hex = this.key.hex();
                        this.wif = S.privateKeyToWif(this.key, A);
                    } else {
                        this.wif = k;
                        this.key = S.wifToPrivateKey(k, {hex: false});
                        this.hex = this.key.hex();
                        this.compressed = ![S.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                            S.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                        this.testnet = [S.TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX,
                            S.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);

                    }
                } else {
                    k = BF(k);
                    if (k.length !== 32) throw new Error('private key invalid');
                    this.compressed = A.compressed;
                    this.testnet = A.testnet;
                    this.key = k;
                    this.hex = this.key.hex();
                    this.wif = S.privateKeyToWif(this.key, A);
                }
            }
        }
    }

    PrivateKey.prototype.toString = function () {
        return `${this.wif}`;
    };


    class PublicKey {
        constructor(k, A = {}) {
            defArgs(A, {compressed: true, testnet: false});
            this.compressed = A.compressed;
            this.testnet = A.testnet;
            if (k instanceof PrivateKey) {
                A.testnet = k.testnet;
                k = k.wif;
            }

            if (S.isString(k)) {
                if (S.isHex(k)) k = BF(k, 'hex');
                else if (S.isWifValid(k)) {
                    this.compressed = ![S.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                        S.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                    this.testnet = [S.TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX,
                        S.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                    k = S.privateToPublicKey(k, {compressed: this.compressed, testnet: this.testnet, hex: false});
                } else throw new Error('private/public key invalid');
            } else k = BF(k);
            if (k.length === 32) {
                this.key = S.privateToPublicKey(k, {compressed: A.compressed, testnet: A.testnet, hex: false});
                this.compressed = A.compressed;
                this.testnet = A.testnet;
                this.hex = this.key.hex();
            } else if (S.isPublicKeyValid(k)) {
                this.hex = k.hex();
                this.key = k;
                this.compressed = (this.key.length === 33);
                this.testnet = A.testnet;
            } else throw new Error('private/public key invalid');
        }
    }

    PublicKey.prototype.toString = function () {
        return `${this.hex}`;
    };


    class Address {
        constructor(k, A = {}) {
            defArgs(A, {addressType: "P2WPKH", testnet: false, compressed: true});

            if (k === undefined) {
                this.privateKey = new PrivateKey(undefined, A);
                this.publicKey = new PublicKey(this.privateKey, A);
            } else if (S.isString(k)) {
                if (S.isWifValid(k)) {
                    this.privateKey = new PrivateKey(k, A);
                    this.publicKey = new PublicKey(this.privateKey, A);
                    A.testnet = this.privateKey.testnet;
                }
                else if (S.isHex(k)) k = BF(k, 'hex');
                else {
                    throw new Error('private/public key invalid');
                }
            }
            else if (k instanceof PrivateKey) {
                this.privateKey = k;
                A.testnet = k.testnet;
                A.compressed = k.compressed;
                this.publicKey = new PublicKey(this.privateKey, A);
            } else if (k instanceof PublicKey) {
                A.testnet = k.testnet;
                A.compressed = k.compressed;
                this.publicKey = k;
            } else {
                if (!Buffer.isBuffer(k)) k = BF(k);

                if (k.length === 32) {
                    this.privateKey = new PrivateKey(k, A);
                    this.publicKey = new PublicKey(this.privateKey, A);
                } else if (S.isPublicKeyValid(k)) {
                    this.publicKey = new PublicKey(key, A);
                } else throw new Error('private/public key invalid');
                this.testnet = A.testnet;
            }

            if (!["P2PKH", "PUBKEY", "P2WPKH", "P2SH_P2WPKH"].includes(A.addressType)) {
                throw new Error('address type invalid');
            }

            this.type = A.addressType;
            if (this.type === 'PUBKEY') {
                this.publicKeyScript = BC([S.opPushData(this.publicKey.key), BF([O.OP_CHECKSIG])])
                this.publicKeyScriptHex = this.publicKeyScript.hex()
            }
            this.witnessVersion = (this.type === "P2WPKH") ? 0 : null;
            if (this.type === "P2SH_P2WPKH") {
                this.scriptHash = true;
                this.redeemScript = S.publicKeyTo_P2SH_P2WPKH_Script(this.publicKey.key);
                this.redeemScriptHex = this.redeemScript.hex();
                this.hash = S.hash160(this.redeemScript);
                this.witnessVersion = null;
            } else {
                this.scriptHash = false;
                this.hash = S.hash160(this.publicKey.key);
            }
            this.hashHex = this.hash.hex();
            this.testnet = A.testnet;
            this.address = S.hashToAddress(this.hash, {
                scriptHash: this.scriptHash,
                witnessVersion: this.witnessVersion, testnet: this.testnet
            });
        }
    }

    Address.prototype.toString = function () {
        return `${this.address}`;
    };

    class ScriptAddress {
        constructor(s, A = {}) {
            defArgs(A, {witnessVersion: 0, testnet: false});
            this.witnessVersion = A.witnessVersion;
            this.testnet = A.testnet;
            s = getBuffer(s);
            this.script = s;
            this.scriptHex = s.hex();
            if (this.witnessVersion === null) this.hash = S.hash160(this.script);
            else this.hash = S.sha256(this.script);
            this.scriptOpcodes = S.decodeScript(this.script);
            this.scriptOpcodesAsm = S.decodeScript(this.script, {asm: true});
            this.address = S.hashToAddress(this.hash, {
                scriptHash: true,
                witnessVersion: this.witnessVersion, testnet: this.testnet
            });
        }

        static multisig(n, m, keyList, A = {}) {
            if ((n > 15) || (m > 15) || (n > m) || (n < 1) || (m < 1))
                throw new Error('invalid n of m maximum 15 of 15 multisig allowed');
            if (keyList.length !== m)
                throw new Error('invalid address list count');
            let s = [BF([0x50 + n])];
            for (let k of keyList) {
                if (S.isString(k)) {
                    if (S.isHex(k)) k = BF(k, 'hex');
                    else if (S.isWifValid(k)) k = S.privateToPublicKey(k, {hex: false});
                    else throw new Error('invalid key in key list');
                }
                if (k instanceof Address) k = k.publicKey.key;
                if (k instanceof PrivateKey) k = S.privateToPublicKey(k.publicKey.key);
                if (!Buffer.isBuffer(k)) k = BF(k);

                if (k.length === 32) k = S.privateToPublicKey(k);
                if (k.length !== 33) throw new Error('invalid public key list element size');
                s.push(BC([BF(S.intToVarInt(k.length)), k]));
            }
            s.push(BF([0x50 + m, O.OP_CHECKMULTISIG]))
            s = BC(s);
            return new ScriptAddress(s, A);
        }
    }

    ScriptAddress.prototype.toString = function () {
        return `${this.address}`;
    };

    S.PrivateKey = PrivateKey;
    S.PublicKey = PublicKey;
    S.ScriptAddress = ScriptAddress;
    S.Address = Address;
};


