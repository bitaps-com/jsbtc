module.exports = function (constants, hash, encoders, tools, opcodes, address, key, script) {
    let T = tools;
    let Buffer = T.Buffer;
    let defArgs = T.defArgs;
    let getBuffer = T.getBuffer;
    let B = Buffer.from;
    let BC = Buffer.concat;
    let O = opcodes.OPCODE;
    let C = constants;

    class PrivateKey {
        constructor(k, A = {}) {
            defArgs(A, {compressed: true, testnet: false});
            if (k === undefined) {
                this.compressed = A.compressed;
                this.testnet = A.testnet;
                this.key = key.createPrivateKey({wif: false});
                this.hex = this.key.hex();
                this.wif = key.privateKeyToWif(this.key, A);
            } else {
                if (T.isString(k)) {
                    if (T.isHex(k)) {
                        this.key = B(k, 'hex');
                        this.compressed = A.compressed;
                        this.testnet = A.testnet;
                        this.hex = this.key.hex();
                        this.wif = key.privateKeyToWif(this.key, A);
                    } else {
                        this.wif = k;
                        this.key = key.wifToPrivateKey(k, {hex: false});
                        this.hex = this.key.hex();
                        this.compressed = ![C.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                            C.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                        this.testnet = [C.TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX,
                            C.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                    }
                } else {
                    k = B(k);
                    if (k.length !== 32) throw new Error('private key invalid');
                    this.compressed = A.compressed;
                    this.testnet = A.testnet;
                    this.key = k;
                    this.hex = this.key.hex();
                    this.wif = key.privateKeyToWif(this.key, A);
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
                k = k.wif;
                A.testnet = k.testnet;
            }

            if (T.isString(k)) {
                if (T.isHex(k)) k = B(k, 'hex');
                else if (key.isWifValid(k)) {
                    this.compressed = ![C.MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                        C.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                    this.testnet = [C.TESTNET_PRIVATE_KEY_COMPRESSED_PREFIX,
                        C.TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX].includes(k[0]);
                    k = key.privateToPublicKey(k, {compressed: this.compressed, testnet: this.testnet, hex: false});
                } else throw new Error('private/public key invalid');
            } else k = B(k);
            if (k.length === 32) {
                this.key = key.privateToPublicKey(k, {compressed: A.compressed, testnet: A.testnet, hex: false});
                this.compressed = A.compressed;
                this.testnet = A.testnet;
                this.hex = this.key.hex();
            } else if (key.isPublicKeyValid(k)) {
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
            defArgs(A, {address_type: "P2WPKH", testnet: false, compressed: true});

            if (k === undefined) {
                this.privateKey = new PrivateKey(undefined, A);
                this.publicKey = new PublicKey(this.privateKey, A);
            } else if (T.isString(k)) {
                if (key.isWifValid(k)) {
                    this.privateKey = new PrivateKey(k, A);
                    this.publicKey = new PublicKey(this.privateKey, A);
                }
                if (T.isHex(k)) k = B(k, 'hex');
                else throw new Error('private/public key invalid');
            }

            if (k instanceof PrivateKey) {
                this.privateKey = k;
                A.testnet = k.testnet;
                A.compressed = k.compressed;
                this.publicKey = new PublicKey(this.privateKey, A);
            } else if (k instanceof PublicKey) {
                A.testnet = k.testnet;
                A.compressed = k.compressed;
                this.publicKey = k;
            } else {
                if (!Buffer.isBuffer(k)) k = B(k);

                if (k.length === 32) {
                    this.privateKey = new PrivateKey(k, A);
                    this.publicKey = new PublicKey(this.privateKey, A);
                } else if (key.isPublicKeyValid(k)) {
                    this.publicKey = new PublicKey(key, A);
                } else throw new Error('private/public key invalid');
                this.testnet = A.testnet;
            }

            if (!["P2PKH", "PUBKEY", "P2WPKH", "P2SH_P2WPKH"].includes(A.address_type)) {
                throw new Error('address type invalid');
            }

            this.type = A.address_type;
            if (this.type === 'PUBKEY') {
                this.publicKeyScript = BC([script.opPushData(this.publicKey.key), B([O.OP_CHECKSIG])])
                this.publicKeyScriptHex = this.publicKeyScript.hex()
            }
            this.witnessVersion = (this.type === "P2WPKH") ? 0 : null;
            if (this.type === "P2SH_P2WPKH") {
                this.scriptHash = true;
                this.redeemScript = script.publicKeyTo_P2SH_P2WPKH_Script(this.publicKey.key);
                this.redeemScriptHex = this.redeemScript.hex();
                this.hash = hash.hash160(this.redeemScript);
                this.witnessVersion = null;
            } else {
                this.scriptHash = false;
                this.hash = hash.hash160(this.publicKey.key);
            }
            this.hashHex = this.hash.hex();
            this.address = address.hashToAddress(this.hash, {
                script_hash: this.scriptHash,
                witness_version: this.witnessVersion, testnet: this.testnet
            });
        }
    }

    Address.prototype.toString = function () {
        return `${this.address}`;
    };

    class ScriptAddress {
        constructor(s, A = {}) {
            defArgs(A, {witness_version: 0, testnet: false});
            this.witnessVersion = A.witness_version;
            this.testnet = A.testnet;
            s = getBuffer(s);
            this.script = s;
            this.scriptHex = s.hex();
            if (this.witnessVersion === null) this.hash = hash.hash160(this.script);
            else this.hash = hash.sha256(this.script);
            this.scriptOpcodes = script.decodeScript(this.script);
            this.scriptOpcodesAsm = script.decodeScript(this.script, {asm: true});
            this.address = address.hashToAddress(this.hash, {
                script_hash: true,
                witness_version: this.witnessVersion, testnet: this.testnet
            });
        }

        static multisig(n, m, key_list, A = {}) {
            if ((n > 15) || (m > 15) || (n > m) || (n < 1) || (m < 1))
                throw new Error('invalid n of m maximum 15 of 15 multisig allowed');
            if (key_list.length !== m)
                throw new Error('invalid address list count');
            let s = B([0x50 + n]);
            for (let k of key_list) {
                if (T.isString(k)) {
                    if (T.isHex(k)) k = B(k, 'hex');
                    else if (key.isWifValid(k)) k = key.privateToPublicKey(k, {hex: false});
                    else throw new Error('invalid key in key list');
                }
                if (k instanceof Address) k = k.publicKey.key;
                if (k instanceof PrivateKey) k = key.privateToPublicKey(k.publicKey.key);
                if (!Buffer.isBuffer(k)) k = B(k);

                if (k.length === 32) k = key.privateToPublicKey(key);
                if (k.length !== 33) throw new Error('invalid public key list element size');
                s = BC([s, T.intToVarInt(k), k]);
            }
            s = BC([s, B([0x50 + n, O.OP_CHECKMULTISIG])]);
            return new ScriptAddress(s, A);
        }
    }

    ScriptAddress.prototype.toString = function () {
        return `${this.address}`;
    };

    return {
        PrivateKey: PrivateKey,
        PublicKey: PublicKey,
        ScriptAddress: ScriptAddress,
        Address: Address
    }

};


