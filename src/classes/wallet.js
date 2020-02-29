module.exports = function (S) {
    let Buffer = S.Buffer;
    let defArgs = S.defArgs;
    let getBuffer = S.getBuffer;
    let BF = Buffer.from;
    let BC = Buffer.concat;
    let O = S.OPCODE;
    let ARGS = S.defArgs;

    class Wallet {
        constructor(from = null, A = {}) {
            ARGS(A, {passphrase: "", path: "BIP84", testnet: false, strength: 256, threshold: 1, shares: 1});
            if (A.path === "BIP84") {
                this.pathType = "BIP84";
                this.path = "m/84'/0'/0'/0"
            }
            else if (A.path === "BIP49") {
                this.pathType = "BIP49";
                this.path = "m/49'/0'/0'/0"
            }
            else if (A.path === "BIP44") {
                this.pathType = "BIP49";
                this.path = "m/44'/0'/0'/0"
            } else {
                this.pathType = "custom";
                this.path = A.path;
            }
            this.decodedPath = S.__decodeParh(A.path);
            this.seed = null;
            this.mnemonic = null;
            this.passphrase = A.passphrase;
            this.masterXPrivateKey = null;
            this.accountXPrivateKey = null;
            this.accountXPublicKey = null;
            this.externalChainXPrivateKey = null;
            this.externalChainXPublicKey = null;
            this.internalChainXPrivateKey = null;
            this.internalChainXPublicKey = null;
            let fromType = null;
            if (from === null) {
                let e = S.generateEntropy(A.strength);
                this.mnemonic = S.entropyToMnemonic(e);
                this.seed = S.mnemonicToSeed(this.mnemonic, {hex: true});
                this.from = S.createMasterXPrivateKey(this.seed, {testnet: A.testnet});
                if (this.pathType !== "custom")
                    this.from = S.BIP32_XKeyToPathXKey(this.from, this.pathType);
                fromType = "xPriv";
            }
            else if (S.isString(from)) {
                if (S.isXPrivateKeyValid(from)) {

                }
                else if (S.isXPublicKeyValid(from)) {

                }
                else {
                    // menmonic
                }

            }






        }
    }


    S.Wallet = Wallet;
};


