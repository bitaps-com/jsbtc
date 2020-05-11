module.exports = function (S) {
    let Buffer = S.Buffer;
    let defArgs = S.defArgs;
    let getBuffer = S.getBuffer;
    let BF = Buffer.from;
    let BC = Buffer.concat;
    let O = S.OPCODE;
    let ARGS = S.defArgs;

    class Wallet {
        constructor(A = {}) {
            ARGS(A, {
                from: null,
                passphrase: "", path: null, testnet: false,
                strength: 256, threshold: 1, shares: 1, wordList: S.BIP39_WORDLIST,
                addressType: null, hardenedAddresses: false, account: 0, chain: 0
            });
            this.account = A.account;
            this.chain = A.chain;
            this.hardenedAddresses = A.hardenedAddresses;
            if (A.path === "BIP84") {
                this.pathType = "BIP84";
                this.path = `m/84'/0'/${this.account}'/${this.chain}`;
            } else if (A.path === "BIP49") {
                this.pathType = "BIP49";
                this.path = `m/49'/0'/${this.account}'/${this.chain}`;
            } else if (A.path === "BIP44") {
                this.pathType = "BIP44";
                this.path = `m/44'/0'/${this.account}'/${this.chain}`;
            } else if (A.path !== null) {
                this.pathType = "custom";
                this.path = A.path;
            } else {
                this.pathType = null;
                this.path = null;
            }
            let from = A.from;
            this.from = from;

            let fromType = null;
            if (from === null) {
                let e = S.generateEntropy({strength: A.strength});
                this.mnemonic = S.entropyToMnemonic(e, {wordList: A.wordList});
                this.seed = S.mnemonicToSeed(this.mnemonic, {
                    hex: true, wordList: A.wordList,
                    passphrase: A.passphrase
                });
                this.passphrase = A.passphrase;
                from = S.createMasterXPrivateKey(this.seed, {testnet: A.testnet});
                if (this.pathType === null) {
                    this.pathType = "BIP84";
                    this.path = `m/84'/0'/${this.account}'/${this.chain}`;
                }
                if ((this.pathType !== null) && (this.pathType !== "custom"))
                    from = S.BIP32_XKeyToPathXKey(from, this.pathType);

                fromType = "xPriv";
            } else if (S.isString(from)) {

                if (S.isXPrivateKeyValid(from)) {
                    if (this.pathType === null) {
                        this.pathType = S.xKeyDerivationType(from);
                        if (this.pathType === "BIP84") {
                            this.path = `m/84'/0'/${this.account}'/${this.chain}`;
                        } else if (this.pathType === "BIP49") {
                            this.path = `m/49'/0'/${this.account}'/${this.chain}`;
                        } else if (this.pathType === "BIP44") {
                            this.path = `m/44'/0'/${this.account}'/${this.chain}`;
                        } else {
                            this.path = "m"
                        }
                    }

                    if ((this.pathType !== null) && (this.pathType !== 'custom'))
                        from = S.BIP32_XKeyToPathXKey(S.pathXKeyTo_BIP32_XKey(from), this.pathType);
                    fromType = "xPriv";

                } else if (S.isXPublicKeyValid(from)) {

                    if (this.pathType === null) {
                        this.pathType = S.xKeyDerivationType(from);
                        if (this.pathType === "BIP84") {
                            this.path = `m/84'/0'/${this.account}'/${this.chain}`;
                        } else if (this.pathType === "BIP49") {
                            this.path = `m/49'/0'/${this.account}'/${this.chain}`;
                        } else if (this.pathType === "BIP44") {
                            this.path = `m/44'/0'/${this.account}'/${this.chain}`;
                        } else {
                            this.path = "m"
                        }
                    }
                    if (this.pathType !== "custom") {
                        from = S.BIP32_XKeyToPathXKey(S.pathXKeyTo_BIP32_XKey(from), this.pathType);
                        fromType = "xPub";
                        if (this.depth === 3) this.__path = "";
                    }

                } else {

                    if (!S.isMnemonicValid(from, {wordList: A.BIP39_WORDLIST})) throw new Error("invalid mnemonic");

                    this.mnemonic = from;
                    this.seed = S.mnemonicToSeed(this.mnemonic, {
                        hex: true, wordList: A.wordList,
                        passphrase: A.passphrase
                    });
                    this.passphrase = A.passphrase;
                    from = S.createMasterXPrivateKey(this.seed, {testnet: A.testnet});

                    if (this.pathType === null) {
                        this.pathType = "BIP84";
                        this.path = `m/84'/0'/${this.account}'/${this.chain}`;
                    }
                    if ((this.pathType !== null) && (this.pathType !== "custom"))
                        from = S.BIP32_XKeyToPathXKey(from, this.pathType);
                    fromType = "xPriv";
                }
            } else throw new Error("invalid initial data");


            let rawFrom = S.decodeBase58(from, {checkSum: true, hex: false});
            this.testnet = S.xKeyNetworkType(rawFrom) === 'testnet';
            this.version = rawFrom.slice(0, 4).hex();
            this.depth = rawFrom[4];

            if (this.pathType !== "custom") {
                if ((this.depth === 0) || (this.depth === 3)) {
                    let l = this.path.split('/');
                    this.__path = l.slice(this.depth, 4).join('/');
                } else {
                    this.pathType = 'custom';
                    this.path = "m";
                }
            }

            this.fingerprint = rawFrom.slice(5, 9).hex();
            this.child = rawFrom.readUIntBE(9, 4);
            this.chainCode = rawFrom.slice(9, 4).hex();
            if (fromType === "xPriv") {
                if (this.depth === 0) this.masterXPrivateKey = from;

                if (this.pathType !== "custom") {

                    this.accountXPrivateKey = S.deriveXKey(from, this.__path, {subPath: true});
                    this.accountXPublicKey = S.xPrivateToXPublicKey(this.accountXPrivateKey);

                    this.accountXPrivateKey = S.deriveXKey(from, this.__path, {subPath: true});
                    this.accountXPublicKey = S.xPrivateToXPublicKey(this.accountXPrivateKey);

                    this.externalChainXPrivateKey = S.deriveXKey(from, this.__path + `/${this.chain}`, {subPath: true});
                    this.externalChainXPublicKey = S.xPrivateToXPublicKey(this.externalChainXPrivateKey);

                    this.internalChainXPrivateKey = S.deriveXKey(from, this.__path + `/${this.chain + 1}`, {subPath: true});
                    this.internalChainXPublicKey = S.xPrivateToXPublicKey(this.internalChainXPrivateKey);
                } else {
                    this.chainXPrivateKey = S.deriveXKey(from, this.path);
                    this.chainXPublicKey = S.xPrivateToXPublicKey(this.chainXPrivateKey);
                }


            } else {
                if (this.pathType !== "custom") {
                    this.accountXPublicKey = from;
                    this.externalChainXPublicKey = S.deriveXKey(from, this.__path + `/${this.chain}`, {subPath: true});
                    this.internalChainXPrivateKey = S.deriveXKey(from, this.__path + `/${this.chain + 1}`, {subPath: true});
                } else {
                    this.chainXPublicKey = S.deriveXKey(from, this.path);
                }

            }
            if (this.mnemonic !== null) {
                this.sharesThreshold = A.threshold;
                this.sharesTotal = A.shares;
                if (this.sharesThreshold > this.sharesTotal) throw new Error("Threshold invalid");
                if (this.sharesTotal > 1) {
                    this.mnemonicShares = S.splitMnemonic(A.threshold, A.shares, this.mnemonic,
                        {wordList: A.BIP39_WORDLIST});

                }
            }

            if (A.addressType !== null) this.addressType = A.addressType;
            else {
                if (this.pathType === "BIP84") this.addressType = "P2WPKH";
                else if (this.pathType === "BIP49") this.addressType = "P2SH_P2WPKH";
                else this.addressType = "P2PKH";
            }
        }


    }

    Wallet.prototype.setChain = function (i) {
        self.chain = i;
    };

    Wallet.prototype.getAddress = function (i, external = true) {
        let r = {};
        let h = (this.hardenedAddresses) ? "'" : "";
        if (this.pathType !== 'custom') {
            let p = "m/" + i + h;
            if (external) {
                if (this.externalChainXPrivateKey !== undefined) {
                    let key = S.deriveXKey(this.externalChainXPrivateKey, p);
                    r.privateKey = S.privateFromXPrivateKey(key);
                    r.publicKey = S.privateToPublicKey(r.privateKey);
                } else {
                    let key = S.deriveXKey(this.externalChainXPublicKey, p);

                    r.publicKey = S.publicFromXPublicKey(key);
                }
            } else {
                if (this.internalChainXPrivateKey !== undefined) {
                    let key = S.deriveXKey(this.internalChainXPrivateKey, p);
                    r.privateKey = S.privateFromXPrivateKey(key);
                    r.publicKey = S.privateToPublicKey(r.privateKey);
                } else {
                    let key = S.deriveXKey(this.internalChainXPublicKey, p);
                    r.publicKey = S.publicFromXPublicKey(key);
                }

            }
        } else {

            let p = "m/" + i + h;
            if (this.chainXPrivateKey !== undefined) {
                let key = S.deriveXKey(this.chainXPrivateKey, p);
                r.privateKey = S.privateFromXPrivateKey(key);
                r.publicKey = S.privateToPublicKey(r.privateKey);
            } else {
                let key = S.deriveXKey(this.chainXPublicKey, p);

                r.publicKey = S.publicFromXPublicKey(key);
            }
        }

        if (this.addressType === "P2WPKH") r.address = S.publicKeyToAddress(r.publicKey, {testnet: this.testnet});
        else if (this.addressType === "P2SH_P2WPKH") r.address = S.publicKeyToAddress(r.publicKey,
            {p2sh_p2wpkh: true, testnet: this.testnet});
        else if (this.addressType === "P2PKH") r.address = S.publicKeyToAddress(r.publicKey,
            {witnessVersion: null, testnet: this.testnet});
        return r;
    };

    S.Wallet = Wallet;

};


