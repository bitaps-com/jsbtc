module.exports = function (constants, hash, encoders, tools, opcodes, address, key) {
    let Buffer = tools.Buffer;
    let defArgs = tools.defArgs;
    let getBuffer = tools.getBuffer;
    let B = Buffer.from;
    let BC = Buffer.concat;
    let O = opcodes.OPCODE;
    let C = constants;

    class PrivateKey {
        constructor(k, A= {}) {
            defArgs(A, {compressed: true, testnet: false});
            if (k === undefined) {
                this.compressed = A.compressed;
                this.testnet = A.testnet;
                this.key = key.createPrivateKey({wif: false});
                this.hex= this.key.hex();
                this.wif = key.privateKeyToWif(this.key, A);
            } else {
                if (tools.isString(k)) {
                    if (tools.isHex(k))  {
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
                    if (k.length !== 32)  throw new Error('private key invalid');
                    this.compressed = A.compressed;
                    this.testnet = A.testnet;
                    this.key = k;
                    this.hex= this.key.hex();
                    this.wif = key.privateKeyToWif(this.key, A);
                }
            }
        }
    }

    PrivateKey.prototype.toString = function () {
        return `${this.wif}`;
    };


    class PublicKey {
        constructor(k, A= {}) {
            defArgs(A, {compressed: true, testnet: false});
            this.compressed = A.compressed;
            this.testnet = A.testnet;

            if (tools.isString(k)) {
                if (tools.isHex(k))  k = B(k, 'hex');
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
            }
            else if (key.isPublicKeyValid(k)) {
                this.hex = k.hex();
                this.key = k;
                this.compressed = (this.key.length === 33);
                this.testnet = A.testnet;
            } else  throw new Error('private/public key invalid');
        }
    }
    PublicKey.prototype.toString = function () {
        return `${this.hex}`;
    };

    return {
        PrivateKey: PrivateKey,
        PublicKey: PublicKey
    }
};


