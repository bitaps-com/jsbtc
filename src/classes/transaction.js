module.exports = function (S) {
    let s2rh = S.s2rh;
    let rh2s = S.rh2s;
    let Buffer = S.Buffer;
    let BN = S.BN;
    let isBuffer = S.Buffer.isBuffer;
    let ARGS = S.defArgs;
    let getBuffer = S.getBuffer;
    let BF = Buffer.from;
    let BA = Buffer.alloc;
    let BC = Buffer.concat;
    let O = S.OPCODE
    let iS = S.isString;

    class Transaction {
        constructor(A = {}) {
            ARGS(A, {
                rawTx: null, format: 'decoded', version: 1,
                lockTime: 0, testnet: false, autoCommit: true, keepRawTx: false
            });
            if (!["decoded", "raw"].includes(A.format)) throw new Error('format error, raw or decoded allowed');
            this.autoCommit = A.autoCommit;
            this.format = A.format;
            this.testnet = A.testnet;
            this.segwit = false;
            this.txId = null;
            this.hash = null;
            this.version = A.version;
            this.size = 0;
            this.vSize = 0;
            this.bSize = 0;
            this.vIn = {};
            this.vOut = {};
            this.rawTx = null;
            this.blockHash = null;
            this.confirmations = null;
            this.time = null;
            this.blockTime = null;
            this.blockIndex = null;
            this.coinbase = false;
            this.fee = null;
            this.data = null;
            this.amount = null;
            if (A.rawTx === null) return;
            let tx = getBuffer(A.rawTx);
            this.amount = 0;
            let sw = 0, swLen = 0;
            let start = (tx.__offset === undefined) ? 0 : tx.__offset;
            this.version = tx.readInt(4);
            let n = tx.readVarInt();

            if (n[0] === 0) {
                // segwit format
                sw = 1;
                this.flag = tx.read(1);
                n = tx.readVarInt();
            }
            // inputs
            let ic = S.varIntToInt(n);
            for (let k = 0; k < ic; k++)
                this.vIn[k] = {
                    txId: tx.read(32),
                    vOut: tx.readInt(4),
                    scriptSig: tx.read(S.varIntToInt(tx.readVarInt())),
                    sequence: tx.readInt(4)
                };
            // outputs
            let oc = S.varIntToInt(tx.readVarInt());
            for (let k = 0; k < oc; k++) {
                this.vOut[k] = {};
                this.vOut[k].value = tx.readInt(8);
                this.amount += this.vOut[k].value;
                this.vOut[k].scriptPubKey = tx.read(S.varIntToInt(tx.readVarInt()));
                let s = S.parseScript(this.vOut[k].scriptPubKey);
                this.vOut[k].nType = s.nType;
                this.vOut[k].type = s.type;
                if ((this.data === null) && (s.type === 3)) this.data = s.data;
                if (s.addressHash !== undefined) {
                    this.vOut[k].addressHash = s.addressHash;
                    this.vOut[k].reqSigs = s.reqSigs;
                }
            }

            // witness
            if (sw) {
                sw = tx.__offset - start;
                for (let k = 0; k < ic; k++) {
                    this.vIn[k].txInWitness = [];
                    let t = S.varIntToInt(tx.readVarInt());
                    for (let q = 0; q < t; q++)
                        this.vIn[k].txInWitness.push(tx.read(S.varIntToInt(tx.readVarInt())));
                }
                swLen = (tx.__offset - start) - sw + 2;
            }
            this.lockTime = tx.readInt(4);
            let end = tx.__offset;
            this.rawTx = tx.slice(start, end);
            this.size = end - start;
            this.bSize = end - start - swLen;
            this.weight = this.bSize * 3 + this.size;
            this.vSize = Math.ceil(this.weight / 4);
            this.coinbase = !!((ic === 1) && (this.vIn[0].txId.equals(Buffer(32))) && (this.vIn[0].vOut === 0xffffffff));

            if (sw > 0) {
                this.segwit = true;
                this.hash = S.doubleSha256(this.rawTx);
                this.txId = S.doubleSha256(BC([this.rawTx.slice(0, 4),
                    this.rawTx.slice(6, sw), this.rawTx.slice(this.rawTx.length - 4, this.rawTx.length)]));
            } else {
                this.txId = S.doubleSha256(this.rawTx);
                this.hash = this.txId;
                this.segwit = false;
            }
            if (!A.keepRawTx) this.rawTx = null;
            if (A.format === 'decoded') this.decode();
        }
    }

    // change Transaction object representation to "decoded" human readable format
    Transaction.prototype.decode = function (testnet) {
        this.format = 'decoded';
        if (testnet !== undefined) this.testnet = testnet;
        if (isBuffer(this.txId)) this.txId = rh2s(this.txId);
        if (isBuffer(this.hash)) this.hash = rh2s(this.hash);
        if (isBuffer(this.flag)) this.flag = rh2s(this.flag);
        if (isBuffer(this.rawTx)) this.rawTx = this.rawTx.hex();
        for (let i in this.vIn) {
            if (isBuffer(this.vIn[i].txId)) this.vIn[i].txId = rh2s(this.vIn[i].txId);
            if (isBuffer(this.vIn[i].scriptSig)) this.vIn[i].scriptSig = this.vIn[i].scriptSig.hex();
            if (this.vIn[i].amount instanceof S.BN) this.vIn[i].amount = this.vIn[i].amount.toString(16);
            if (this.vIn[i].txInWitness !== undefined) {
                let t = [];
                for (let w of this.vIn[i].txInWitness) t.push((isBuffer(w) ? w.hex() : w));
                this.vIn[i].txInWitness = t;
            }
            if (isBuffer(this.vIn[i].addressHash)) {
                let w = (this.vIn[i].nType < 5) ? null : this.vIn[i].addressHash[0];
                this.vIn[i].addressHash = this.vIn[i].addressHash.hex();
                let sh = [1, 5].includes(this.vIn[i].nType);
                this.vIn[i].address = S.hashToAddress(this.vIn[i].addressHash,
                    {testnet: this.testnet, scriptHash: sh, witnessVersion: w});

            }
            if (isBuffer(this.vIn[i].scriptPubKey)) {
                this.vIn[i].scriptPubKey = this.vIn[i].scriptPubKey.hex();
                this.vIn[i].scriptPubKeyOpcodes = S.decodeScript(this.vIn[i].scriptPubKey);
                this.vIn[i].scriptPubKeyAsm = S.decodeScript(this.vIn[i].scriptPubKey, {asm: true});
            }
            if (isBuffer(this.vIn[i].redeemScript)) {
                this.vIn[i].redeemScript = this.vIn[i].redeemScript.hex();
                this.vIn[i].redeemScriptOpcodes = S.decodeScript(this.vIn[i].redeemScript);
                this.vIn[i].redeemScriptAsm = S.decodeScript(this.vIn[i].redeemScript, {asm: true});
            }
            if (!this.coinbase) {
                if (isBuffer(this.vIn[i].scriptSig)) {
                    this.vIn[i].scriptSig = this.vIn[i].scriptSig.hex();
                }

                this.vIn[i].scriptSigOpcodes = S.decodeScript(this.vIn[i].scriptSig);
                this.vIn[i].scriptSigAsm = S.decodeScript(this.vIn[i].scriptSig, {asm: true});
            }
        }

        for (let i in this.vOut) {
            if (isBuffer(this.vOut[i].addressHash)) {
                let w = (this.vOut[i].nType < 5) ? null : this.vOut[i].scriptPubKey[0];
                this.vOut[i].addressHash = this.vOut[i].addressHash.hex();
                let sh = [1, 5].includes(this.vOut[i].nType);
                this.vOut[i].address = S.hashToAddress(this.vOut[i].addressHash,
                    {testnet: this.testnet, scriptHash: sh, witnessVersion: w});

            }
            if (isBuffer(this.vOut[i].scriptPubKey)) {
                this.vOut[i].scriptPubKey = this.vOut[i].scriptPubKey.hex();
                this.vOut[i].scriptPubKeyOpcodes = S.decodeScript(this.vOut[i].scriptPubKey);
                this.vOut[i].scriptPubKeyAsm = S.decodeScript(this.vOut[i].scriptPubKey, {asm: true});
            }


        }
        if (isBuffer(this.data)) this.data = this.data.hex();
        return this;
    };

    Transaction.prototype.encode = function () {
        if (iS(this.txId)) this.txId = s2rh(this.txId);
        if (iS(this.flag)) this.flag = s2rh(this.flag);
        if (iS(this.hash)) this.hash = s2rh(this.hash);
        if (iS(this.rawTx)) this.rawTx = BF(this.hash, 'hex');
        for (let i in this.vIn) {
            if (iS(this.vIn[i].txId)) this.vIn[i].txId = s2rh(this.vIn[i].txId);
            if (iS(this.vIn[i].scriptSig)) this.vIn[i].scriptSig = BF(this.vIn[i].scriptSig, 'hex');
            if (this.vIn[i].txInWitness !== undefined) {
                let t = [];
                for (let w of this.vIn[i].txInWitness) t.push((iS(w) ? BF(w, 'hex') : w));
                this.vIn[i].txInWitness = t;
            }
            if (iS(this.vIn[i].addressHash)) this.vIn[i].addressHash = BF(this.vIn[i].addressHash, 'hex');
            if (iS(this.vIn[i].scriptPubKey)) this.vIn[i].scriptPubKey = BF(this.vIn[i].scriptPubKey, 'hex');
            if (iS(this.vIn[i].redeemScript)) this.vIn[i].redeemScript = BF(this.vIn[i].redeemScript, 'hex');
            if (iS(this.vIn[i].addressHash)) this.vIn[i].addressHash = BF(this.vIn[i].addressHash, 'hex');
            delete this.vIn[i].scriptSigAsm;
            delete this.vIn[i].scriptSigOpcodes;
            delete this.vIn[i].scriptPubKeyOpcodes;
            delete this.vIn[i].scriptPubKeyAsm;
            delete this.vIn[i].redeemScriptOpcodes;
            delete this.vIn[i].redeemScriptAsm;
            delete this.vIn[i].address;
        }
        for (let i in this.vOut) {
            if (iS(this.vOut[i].scriptPubKey)) this.vOut[i].scriptPubKey = BF(this.vOut[i].scriptPubKey, 'hex');
            if (iS(this.vOut[i].addressHash)) this.vOut[i].addressHash = BF(this.vOut[i].addressHash, 'hex');
            delete this.address;
            delete this.vOut[i].scriptPubKeyOpcodes;
            delete this.vOut[i].scriptPubKeyAsm;
        }
        if (iS(this.data)) this.data = BF(this.data, 'hex');
        this.format = 'raw';
        return this;
    };

    Transaction.prototype.serialize = function (A = {}) {
        ARGS(A, {segwit: true, hex: true});
        let chunks = [];
        chunks.push(BF(S.intToBytes(this.version, 4)));
        if (A.segwit && this.segwit) chunks.push(BF([0, 1]));
        chunks.push(BF(S.intToVarInt(Object.keys(this.vIn).length)));

        for (let i in this.vIn) {
            if (iS(this.vIn[i].txId)) chunks.push(s2rh(this.vIn[i].txId));
            else chunks.push(this.vIn[i].txId);
            chunks.push(BF(S.intToBytes(this.vIn[i].vOut, 4)));
            let s = (iS(this.vIn[i].scriptSig)) ? BF(this.vIn[i].scriptSig, 'hex') : this.vIn[i].scriptSig;

            chunks.push(BF(S.intToVarInt(s.length)));
            chunks.push(s);
            chunks.push(BF(S.intToBytes(this.vIn[i].sequence, 4)));
        }
        chunks.push(BF(S.intToVarInt(Object.keys(this.vOut).length)));

        for (let i in this.vOut) {
            chunks.push(BF(S.intToBytes(this.vOut[i].value, 8)));
            let s = (iS(this.vOut[i].scriptPubKey)) ? BF(this.vOut[i].scriptPubKey, 'hex') : this.vOut[i].scriptPubKey;
            chunks.push(BF(S.intToVarInt(s.length)));
            chunks.push(s);
        }
        if (A.segwit && this.segwit) {
            for (let i in this.vIn) {
                chunks.push(BF(S.intToVarInt(this.vIn[i].txInWitness.length)));
                for (let w of this.vIn[i].txInWitness) {
                    let s = iS(w) ? BF(w, 'hex') : w;
                    chunks.push(BF(S.intToVarInt(s.length)));
                    chunks.push(s);
                }
            }
        }
        chunks.push(BF(S.intToBytes(this.lockTime, 4)));
        let out = BC(chunks);
        return (A.hex) ? out.hex() : out;
    };

    Transaction.prototype.json = function () {
        let r;
        if (this.format === 'raw') {
            this.decode();
            r = JSON.stringify(this);
            this.encode();
        } else r = JSON.stringify(this);
        return r;
    };

    Transaction.prototype.addInput = function (A = {}) {
        ARGS(A, {
            txId: null, vOut: 0, sequence: 0xffffffff,
            scriptSig: "", txInWitness: null, value: null,
            scriptPubKey: null, address: null, privateKey: null,
            redeemScript: null, inputVerify: true
        });
        let witness = [], s;
        if (A.txId === null) {
            A.txId = Buffer(32);
            A.vOut = 0xffffffff;
            if (((A.sequence !== 0xffffffff) || (Object.keys(this.vOut).length)) && (A.inputVerify))
                throw new Error('invalid coinbase transaction');
        }
        if (iS(A.txId))
            if (S.isHex(A.txId)) A.txId = s2rh(A.txId);
            else throw new Error('txId invalid');
        if (!isBuffer(A.txId) || A.txId.length !== 32) throw new Error('txId invalid');

        if (A.scriptSig.length === 0) A.scriptSig = BF([]);
        if (iS(A.scriptSig))
            if (S.isHex(A.scriptSig)) A.scriptSig = BF(A.scriptSig, 'hex');
            else throw new Error('scriptSig invalid');
        if (!isBuffer(A.scriptSig) || ((A.scriptSig.length > 520) && (A.inputVerify)))
            throw new Error('scriptSig invalid');

        if ((A.vOut < 0) || A.vOut > 0xffffffff) throw new Error('vOut invalid');
        if ((A.sequence < 0) || A.sequence > 0xffffffff) throw new Error('vOut invalid');

        if ((A.privateKey !== null) && (!(A.privateKey instanceof S.PrivateKey)))
            A.privateKey = S.PrivateKey(A.privateKey);

        if ((A.value !== null) && ((A.value < 0) || (A.value > S.MAX_AMOUNT)))
            throw new Error('amount invalid');

        if (A.txInWitness !== null) {
            let l = 0;
            for (let w of A.txInWitness) {
                if (iS(w)) witness.push((this.format === 'raw') ? BF(w, 'hex') : w);
                else witness.push((this.format === 'raw') ? w : BF(w, 'hex'));
                l += 1 + w.length;
            }
        }

        if (A.txId.equals(Buffer.alloc(32))) {
            if (!((A.vOut === 0xffffffff) && (A.sequence === 0xffffffff) && (A.scriptSig.length <= 100)))
                if (A.inputVerify) throw new Error("coinbase tx invalid");
            this.coinbase = true;
        }

        if (A.scriptPubKey !== null) {
            if (iS(A.scriptPubKey)) A.scriptPubKey = BF(A.scriptPubKey, 'hex');
            if (!isBuffer(A.scriptPubKey)) throw new Error("scriptPubKey invalid");
        }

        if (A.redeemScript !== null) {
            if (iS(A.redeemScript)) A.redeemScript = BF(A.redeemScript, 'hex');
            if (!isBuffer(A.redeemScript)) throw new Error("scriptPubKey invalid");
        }

        if (A.address !== null) {
            if (iS(A.address)) {
                let net = S.addressNetType(A.address) === 'mainnet';
                if (!(net !== this.testnet)) throw new Error("address invalid");
                s = S.addressToScript(A.address);
            } else if (A.address.address !== undefined) s = S.addressToScript(A.address.address);
            else throw new Error("address invalid");
            if (A.scriptPubKey !== null) {
                if (!A.scriptPubKey.equals(s)) throw new Error("address not match script");
            } else A.scriptPubKey = s;

        }

        let k = Object.keys(this.vIn).length;
        this.vIn[k] = {};
        this.vIn[k].vOut = A.vOut;
        this.vIn[k].sequence = A.sequence;
        if (this.format === 'raw') {
            this.vIn[k].txId = A.txId;
            this.vIn[k].scriptSig = A.scriptSig;
            if (A.scriptPubKey !== null) this.vIn[k].scriptPubKey = A.scriptPubKey;
            if (A.redeemScript !== null) this.vIn[k].redeemScript = A.redeemScript;
        } else {
            this.vIn[k].txId = rh2s(A.txId);
            this.vIn[k].scriptSig = A.scriptSig.hex();
            this.vIn[k].scriptSigOpcodes = S.decodeScript(A.scriptSig);
            this.vIn[k].scriptSigAsm = S.decodeScript(A.scriptSig, {asm: true});
            if (A.scriptPubKey !== null) {
                this.vIn[k].scriptPubKey = A.scriptPubKey.hex();
                this.vIn[k].scriptPubKeyOpcodes = S.decodeScript(A.scriptPubKey);
                this.vIn[k].scriptPubKeyAsm = S.decodeScript(A.scriptPubKey, {asm: true});
            }
            if (A.redeemScript !== null) {
                this.vIn[k].redeemScript = A.redeemScript.hex();
                this.vIn[k].redeemScriptOpcodes = S.decodeScript(A.redeemScript);
                this.vIn[k].redeemScriptAsm = S.decodeScript(A.redeemScript, {asm: true});
            }
        }

        if (A.txInWitness !== null) {
            this.segwit = true;
            this.vIn[k].txInWitness = witness
        }
        if (A.value !== null) this.vIn[k].value = A.value;
        if (A.privateKey !== 0) this.vIn[k].privateKey = A.privateKey;
        if (this.autoCommit) this.commit();
        return this;
    };

    Transaction.prototype.addOutput = function (A = {}) {
        ARGS(A, {value: 0, address: null, scriptPubKey: null});
        if ((A.address === null) && (A.scriptPubKey === null))
            throw new Error("unable to add output, address or script required");
        if ((A.value < 0) || (A.value > S.MAX_AMOUNT)) throw new Error(" amount value error");
        if (A.scriptPubKey !== null)
            if (iS(A.scriptPubKey)) A.scriptPubKey = BF(A.scriptPubKey, 'hex');
            else if (A.address !== null)
                if (A.address.address !== undefined) A.address = A.address.address;
        if (A.address !== null)
            A.scriptPubKey = S.addressToScript(A.address);


        let k = Object.keys(this.vOut).length;
        this.vOut[k] = {};
        this.vOut[k].value = A.value;

        let s = S.parseScript(A.scriptPubKey, {segwit: true});
        this.vOut[k].nType = s.nType;
        this.vOut[k].type = s.type;

        if (this.format === 'raw') {
            this.vOut[k].scriptPubKey = A.scriptPubKey;
            if ((this.data === null) && (s.nType === 3)) this.data = s.data;
            if (!([3, 4, 7, 8].includes(s.nType))) {
                this.vOut[k].addressHash = s.addressHash;
                this.vOut[k].reqSigs = s.reqSigs;
            }
        } else {
            this.vOut[k].scriptPubKey = A.scriptPubKey.hex();
            if ((this.data === null) && (s.nType === 3)) this.data = s.data.hex();
            if (!([3, 4, 7, 8].includes(s.nType))) {
                this.vOut[k].addressHash = s.addressHash.hex();
                this.vOut[k].reqSigs = s.reqSigs;
            }
            this.vOut[k].scriptPubKeyOpcodes = S.decodeScript(A.scriptPubKey);
            this.vOut[k].scriptPubKeyAsm = S.decodeScript(A.scriptPubKey, {"asm": true});
            let sh = [1, 5].includes(s.nType);
            let witnessVersion = (s.nType < 5) ? null : A.scriptPubKey[0];
            if (this.vOut[k].addressHash !== undefined)
                this.vOut[k].address = S.hashToAddress(this.vOut[k].addressHash,
                    {testnet: this.testnet, scriptHash: sh, witnessVersion: witnessVersion});
        }
        if (this.autoCommit) this.commit();
        return this;
    };

    Transaction.prototype.delOutput = function (n) {
        let l = Object.keys(this.vOut).length;
        if (l === 0) return this;
        if (n === undefined) n = l - 1;
        let out = {};
        let c = 0;
        for (let i = 0; i < l; i++) {
            if (i !== n) {
                out[c] = this.vOut[i];
                c++;
            }
        }
        this.vOut = out;
        if (this.autoCommit) this.commit();
        return this;
    };

    Transaction.prototype.delInput = function (n) {
        let l = Object.keys(this.vIn).length;
        if (l === 0) return this;
        if (n === undefined) n = l - 1;
        let out = {};
        let c = 0;
        for (let i = 0; i < l; i++) {
            if (i !== n) {
                out[c] = this.vIn[i];
                c++;
            }
        }
        this.vOut = out;
        if (this.autoCommit) this.commit();
        return this;
    };

    Transaction.prototype.commit = function () {
        if ((Object.keys(this.vIn).length === 0) || (Object.keys(this.vOut).length === 0)) return this;

        if (this.segwit)
            for (let i in this.vIn) if (this.vIn[i].txInWitness === undefined) this.vIn[i].txInWitness = [];
        let nonSegwitView = this.serialize({segwit: false, hex: false});
        this.txId = S.doubleSha256(nonSegwitView);
        this.rawTx = this.serialize({segwit: true, hex: false});
        this.hash = S.doubleSha256(this.rawTx);
        this.size = this.rawTx.length;
        this.bSize = nonSegwitView.length;
        this.weight = this.bSize * 3 + this.size;
        this.vSize = Math.ceil(this.weight / 4);

        if (this.format !== 'raw') {
            this.txId = rh2s(this.txId);
            this.hash = rh2s(this.hash);
            this.rawTx = this.rawTx.hex();
        }
        let inputSum = 0;
        let outputSum = 0;
        for (let i in this.vIn) {
            if (this.vIn[i].value !== undefined) inputSum += this.vIn[i].value;
            else {
                inputSum = null;
                break
            }

            for (let i in this.vOut)
                if (this.vOut[i].value !== undefined) outputSum += this.vOut[i].value;
        }
        this.amount = outputSum;
        if (outputSum && inputSum) this.fee = inputSum - outputSum;
        else this.fee = null;
        return this;
    };

    Transaction.prototype.sigHash = function (n, A = {}) {
        ARGS(A, {scriptPubKey: null, sigHashType: S.SIGHASH_ALL, preImage: false});
        if (this.vIn[n] === undefined) throw new Error("input not exist");
        let scriptCode;
        if (A.scriptPubKey !== null) scriptCode = A.scriptPubKey;
        else {
            if (this.vIn[n].scriptPubKey === undefined) throw new Error("scriptPubKey required");
            scriptCode = this.vIn[n].scriptPubKey;
        }
        scriptCode = getBuffer(scriptCode);

        if (((A.sigHashType & 31) === S.SIGHASH_SINGLE) && (n >= Object.keys(this.vOut).length)) {
            let r = BC([BF([1]), BA(31)]);
            return (this.format === 'raw') ? r : rh2s(r);
        }

        scriptCode = S.deleteFromScript(scriptCode, BF([O.OP_CODESEPARATOR]));
        let pm = [BF(S.intToBytes(this.version, 4))];
        pm.push((A.sigHashType & S.SIGHASH_ANYONECANPAY) ? BF([1]) : BF(S.intToVarInt(Object.keys(this.vIn).length)));

        for (let i in this.vIn) {
            i = parseInt(i);
            if ((A.sigHashType & S.SIGHASH_ANYONECANPAY) && (n !== i)) continue;
            let sequence = this.vIn[i].sequence;
            if (([S.SIGHASH_SINGLE, S.SIGHASH_NONE].includes(A.sigHashType & 31)) && (n !== i)) sequence = 0;
            let txId = iS(this.vIn[i].txId) ? s2rh(this.vIn[i].txId) : this.vIn[i].txId;
            pm.push(txId);
            pm.push(BF(S.intToBytes(this.vIn[i].vOut, 4)));

            if (n === i) {
                pm.push(BF(S.intToVarInt(scriptCode.length)));
                pm.push(scriptCode);
                pm.push(BF(S.intToBytes(sequence, 4)));
            } else {
                pm.push(BF([0]));
                pm.push(BF(S.intToBytes(sequence, 4)));
            }
        }

        if ((A.sigHashType & 31) === S.SIGHASH_NONE) pm.push(BF([0]));
        else if ((A.sigHashType & 31) === S.SIGHASH_SINGLE) pm.push(BF(S.intToVarInt(n + 1)));
        else pm.push(BF(S.intToVarInt(Object.keys(this.vOut).length)));
        let scriptPubKey;

        if ((A.sigHashType & 31) !== S.SIGHASH_NONE) {
            for (let i in this.vOut) {
                i = parseInt(i);
                scriptPubKey = this.vOut[i].scriptPubKey;
                scriptPubKey = iS(scriptPubKey) ? BF(scriptPubKey, 'hex') : scriptPubKey;

                if ((i > n) && ((A.sigHashType & 31) === S.SIGHASH_SINGLE)) continue;
                if (((A.sigHashType & 31) === S.SIGHASH_SINGLE) && (n !== i)) {
                    pm.push(BA(8, 0xff));
                    pm.push(BA(1, 0x00));
                } else {
                    pm.push(BF(S.intToBytes(this.vOut[i].value, 8)));
                    pm.push(BF(S.intToVarInt(scriptPubKey.length)));
                    pm.push(scriptPubKey);
                }
            }
        }
        pm.push(BF(S.intToBytes(this.lockTime, 4)));
        pm.push(BF(S.intToBytes(A.sigHashType, 4)));
        pm = BC(pm);
        if (!A.preImage) {
            pm = S.doubleSha256(pm);
            return (this.format === 'raw') ? pm : rh2s(pm);
        }
        return (this.format === 'raw') ? pm : pm.hex();
    };

    Transaction.prototype.sigHashSegwit = function (n, A = {}) {
        ARGS(A, {value: null, scriptPubKey: null, sigHashType: S.SIGHASH_ALL, preImage: false});
        if (this.vIn[n] === undefined) throw new Error("input not exist");
        let scriptCode, value;

        if (A.scriptPubKey !== null) scriptCode = A.scriptPubKey;
        else {
            if (this.vIn[n].scriptPubKey === undefined) throw new Error("scriptPubKey required");
            scriptCode = this.vIn[n].scriptPubKey;
        }
        scriptCode = getBuffer(scriptCode);

        if (A.value !== null) value = A.value;
        else {
            if (this.vIn[n].value === undefined) throw new Error("value required");
            value = this.vIn[n].value;
        }

        let hp = [], hs = [], ho = [], outpoint, nSequence;

        for (let i in this.vIn) {
            i = parseInt(i);
            let txId = this.vIn[i].txId;
            if (iS(txId)) txId = s2rh(txId);

            let vOut = BF(S.intToBytes(this.vIn[i].vOut, 4));
            if (!(A.sigHashType & S.SIGHASH_ANYONECANPAY)) {
                hp.push(txId);
                hp.push(vOut);
                if (((A.sigHashType & 31) !== S.SIGHASH_SINGLE) && ((A.sigHashType & 31) !== S.SIGHASH_NONE))
                    hs.push(BF(S.intToBytes(this.vIn[i].sequence, 4)));
            }
            if (i === n) {
                outpoint = BC([txId, vOut]);
                nSequence = BF(S.intToBytes(this.vIn[i].sequence, 4));
            }
        }
        let hashPrevouts = (hp.length > 0) ? S.doubleSha256(BC(hp)) : BA(32, 0);
        let hashSequence = (hs.length > 0) ? S.doubleSha256(BC(hs)) : BA(32, 0);
        value = BF(S.intToBytes(value, 8));

        for (let o in this.vOut) {
            o = parseInt(o);
            let scriptPubKey = getBuffer(this.vOut[o].scriptPubKey);
            if (!([S.SIGHASH_SINGLE, S.SIGHASH_NONE].includes(A.sigHashType & 31))) {
                ho.push(BF(S.intToBytes(this.vOut[o].value, 8)));
                ho.push(BF(S.intToVarInt(scriptPubKey.length)));
                ho.push(scriptPubKey);
            } else if (((A.sigHashType & 31) === S.SIGHASH_SINGLE) && (n < Object.keys(this.vOut).length)) {
                if (o === n) {
                    ho.push(BF(S.intToBytes(this.vOut[o].value, 8)));
                    ho.push(BF(S.intToVarInt(scriptPubKey.length)));
                    ho.push(scriptPubKey);
                }
            }
        }

        let hashOutputs = (ho.length > 0) ? S.doubleSha256(BC(ho)) : BA(32, 0);
        let pm = BC([BF(S.intToBytes(this.version, 4)),
            hashPrevouts, hashSequence, outpoint, scriptCode,
            value, nSequence, hashOutputs,
            BF(S.intToBytes(this.lockTime, 4)),
            BF(S.intToBytes(A.sigHashType, 4))]);

        if (A.preImage) return (this.format === 'raw') ? pm.hex() : pm;
        return S.doubleSha256(pm, {'hex': this.format !== 'raw'});
    };

    Transaction.prototype.signInput = function (n, A = {}) {
        ARGS(A, {
            privateKey: null, scriptPubKey: null, redeemScript: null,
            sigHashType: S.SIGHASH_ALL, address: null, value: null,
            witnessVersion: 0, p2sh_p2wsh: false
        });
        if (this.vIn[n] === undefined) throw new Error('input not exist');
        // privateKey
        if (A.privateKey === null) {
            if (this.vIn[n].privateKey === undefined) throw new Error('no private key');
            A.privateKey = this.vIn[n].privateKey
        }

        if (A.privateKey instanceof Array) {
            A.publicKey = [];
            let pk = [];
            for (let key of A.privateKey) {
                if (key.key !== undefined) key = key.wif;
                A.publicKey.push(S.privateToPublicKey(key, {hex: false}));
                pk.push(new S.PrivateKey(key).key);
            }
            A.privateKey = pk;
        } else {
            if (A.privateKey.key === undefined) {
                let k = new S.PrivateKey(A.privateKey);
                A.privateKey = k.key;
                A.privateKeyCompressed = k.compressed;
            } else {
                A.privateKeyCompressed = A.privateKey.compressed;
                A.privateKey = A.privateKey.key;
            }
            A.publicKey = [S.privateToPublicKey(A.privateKey, {hex: false, compressed: A.privateKeyCompressed})];
            A.privateKey = [A.privateKey];
        }

        // address

        if ((A.address === null)&&(this.vIn[n].address !== undefined))  A.address = this.vIn[n].address;
        if (A.address !== null) {
            if (A.address.address !== undefined) A.address = A.address.address;

            if (this.testnet !== (S.addressNetType(A.address) === 'testnet'))
                throw new Error('address network invalid');
            A.scriptPubKey = S.addressToScript(A.address);
        }

        let scriptType = null;

        // redeem script
        if ((A.redeemScript === null)&&(this.vIn[n].redeemScript !== undefined))  A.redeemScript = this.vIn[n].redeemScript;
        if (A.redeemScript !== null)  A.redeemScript = getBuffer(A.redeemScript);

        // script pub key
        if ((A.scriptPubKey === null)&&(this.vIn[n].scriptPubKey !== undefined))
            A.scriptPubKey = this.vIn[n].scriptPubKey;
        else if ((A.scriptPubKey === null)&&(A.redeemScript === null)) throw new Error('no scriptPubKey key');


        if (A.scriptPubKey !== null) {
            A.scriptPubKey = getBuffer(A.scriptPubKey);

            let p = S.parseScript(A.scriptPubKey);
            scriptType = p.type;
            if ([5,6].includes(p.nType)) A.witnessVersion = A.scriptPubKey[0];
        } else if (A.redeemScript !== null) {
            if ((A.witnessVersion === null)||(A.p2sh_p2wsh)) scriptType = "P2SH";
            else scriptType = "P2WSH";
        }

        // sign input
        let sigSript;
        switch (scriptType) {
            case 'PUBKEY':
                sigSript = this.__sign_PUBKEY(n, A);
                break;
            case 'P2PKH':
                sigSript = this.__sign_P2PKH(n, A);
                break;
            case 'P2SH':
                sigSript = this.__sign_P2SH(n, A);
                break;
            case 'P2WPKH':
                sigSript = this.__sign_P2WPKH(n, A);
                break;
            case 'P2WSH':
                sigSript = this.__sign_P2WSH(n, A);
                break;
            case 'MULTISIG':
                sigSript = this.__sign_MULTISIG(n, A);
                break;
            default:
                throw new Error('not implemented');
        }

        if (this.format === 'raw') this.vIn[n].scriptSig = sigSript;
        else {
            this.vIn[n].scriptSig = sigSript.hex();
            this.vIn[n].scriptSigOpcodes = S.decodeScript(sigSript);
            this.vIn[n].scriptSigAsm = S.decodeScript(sigSript, {asm: true});
        }
        if (this.autoCommit) this.commit();
        return this;
    };

    Transaction.prototype.__sign_PUBKEY = function (n, A) {
        let sighash = this.sigHash(n, A);
        if (iS(sighash)) sighash = s2rh(sighash);

        let signature = BC([S.signMessage(sighash, A.privateKey[0]).signature,
            BF(S.intToBytes(A.sigHashType, 1))]);
        if (this.format === 'raw')  this.vIn[n].signatures = [signature];
        else this.vIn[n].signatures = [signature.hex()];
        return BC([BF([signature.length]), signature]);
    };

    Transaction.prototype.__sign_P2PKH = function (n, A) {
        let sighash = this.sigHash(n, A);
        if (iS(sighash)) sighash = s2rh(sighash);
        let signature = BC([S.signMessage(sighash, A.privateKey[0]).signature, BF(S.intToBytes(A.sigHashType, 1))]);
        if (this.format === 'raw')  this.vIn[n].signatures = [signature];
        else this.vIn[n].signatures = [signature.hex()];
        return BC([BF([signature.length]), signature, BF([A.publicKey[0].length]), A.publicKey[0]]);
    };

    Transaction.prototype.__sign_P2SH = function (n, A) {
        if (A.redeemScript === null) throw new Error('no redeem script');
        if (A.p2sh_p2wsh) return this.__sign_P2SH_P2WSH(n, A);
        let scriptType = S.parseScript(A.redeemScript)["type"];
        switch (scriptType) {
            case 'MULTISIG':
                return this.__sign_P2SH_MULTISIG(n, A);
            case 'P2WPKH':
                return this.__sign_P2SH_P2WPKH(n, A);
            default:
                throw new Error('not implemented');
        }
    };

    Transaction.prototype.__sign_P2SH_MULTISIG = function (n, A) {
        let sighash = this.sigHash(n, {scriptPubKey: A.redeemScript, sigHashType: A.sigHashType});

        if (iS(sighash)) sighash = s2rh(sighash);
        let sig = [];
        this.vIn[n].signatures = [];
        for (let key of A.privateKey) {
            let s = BC([S.signMessage(sighash, key).signature,  BF(S.intToBytes(A.sigHashType, 1))]);
            sig.push(s);
            this.vIn[n].signatures.push((this.format === 'raw') ? s : s.hex());
        }
        return this.__get_MULTISIG_scriptSig(n, A.publicKey,
            sig, A.redeemScript, A.redeemScript);
    };

    Transaction.prototype.__sign_P2SH_P2WPKH = function (n, A) {
        let s = BC([BF([0x19]), BF([O.OP_DUP, O.OP_HASH160]),
                   S.opPushData(S.hash160(A.publicKey[0])), BF([O.OP_EQUALVERIFY, O.OP_CHECKSIG])]);
        if (A.value === null) {
            if (this.vIn[n].value !== undefined) A.value = this.vIn[n].value;
            else throw new Error('no input amount');
        }

        let sighash = this.sigHashSegwit(n, {scriptPubKey: s, sigHashType: A.sigHashType, value: A.value});
        sighash = getBuffer(sighash);
        let signature = BC([S.signMessage(sighash, A.privateKey[0]).signature, BF(S.intToBytes(A.sigHashType, 1))]);
        this.segwit = true;
        if (this.format === 'raw') this.vIn[n].txInWitness = [signature, A.publicKey[0]];
        else this.vIn[n].txInWitness = [signature.hex(), A.publicKey[0].hex()];
        this.vIn[n].signatures = (this.format === 'raw') ? [signature] : [signature.hex()];
        return S.opPushData(A.redeemScript);
    };

    Transaction.prototype.__sign_P2SH_P2WSH = function (n, A) {
        let scriptType = S.parseScript(A.redeemScript)["type"];
        switch (scriptType) {
            case 'MULTISIG':
                return this.__sign_P2SH_P2WSH_MULTISIG(n, A);
            default:
                throw new Error('not implemented');
        }
    };

    Transaction.prototype.__sign_P2SH_P2WSH_MULTISIG = function (n, A) {
        this.segwit = true;
        let scriptCode = BC([BF(S.intToVarInt(A.redeemScript.length)), A.redeemScript]);
        let sighash = this.sigHashSegwit(n, {scriptPubKey: scriptCode,
            sigHashType: A.sigHashType, value: A.value});
        sighash = getBuffer(sighash);
        this.vIn[n].signatures = [];
        let sig = [];
        for (let key of A.privateKey) {
            let s = BC([S.signMessage(sighash, key).signature,  BF(S.intToBytes(A.sigHashType, 1))]);
            sig.push(s);
            this.vIn[n].signatures.push((this.format === 'raw') ? s : s.hex());
        }
        let witness =  this.__get_MULTISIG_scriptSig(n, A.publicKey, sig, scriptCode, A.redeemScript, A.value);
        if (this.format === 'raw') this.vIn[n].txInWitness = witness;
        else {
            this.vIn[n].txInWitness = [];
            for (let w of witness) this.vIn[n].txInWitness.push(w.hex());
        }
        // calculate P2SH redeem script from P2WSH redeem script
        return S.opPushData(BC([BF([0]), S.opPushData(S.sha256(A.redeemScript))]))
    };

    Transaction.prototype.__sign_P2WPKH = function (n, A) {
        let s = BC([BF([0x19]), BF([O.OP_DUP, O.OP_HASH160]), A.scriptPubKey.slice(1),
                BF([O.OP_EQUALVERIFY, O.OP_CHECKSIG])]);
        if (A.value === null) {
            if (this.vIn[n].value !== undefined) A.value = this.vIn[n].value;
            else throw new Error('no input amount');
        }
        let sighash = this.sigHashSegwit(n, {scriptPubKey: s, sigHashType: A.sigHashType, value: A.value});
        sighash = getBuffer(sighash);
        let signature = BC([S.signMessage(sighash, A.privateKey[0]).signature, BF(S.intToBytes(A.sigHashType, 1))]);
        this.segwit = true;
        if (this.format === 'raw') this.vIn[n].txInWitness = [signature, A.publicKey[0]];
        else this.vIn[n].txInWitness = [signature.hex(), A.publicKey[0].hex()];
        this.vIn[n].signatures = (this.format === 'raw') ? [signature] : [signature.hex()];
        return BF([]);
    };

    Transaction.prototype.__sign_P2WSH = function (n, A) {
        this.segwit = true;
        if (A.value === null) {
            if (this.vIn[n].value !== undefined) A.value = this.vIn[n].value;
            else throw new Error('no input amount');
        }
        let scriptType = S.parseScript(A.redeemScript)["type"];
        switch (scriptType) {
            case 'MULTISIG':
                return this.__sign_P2WSH_MULTISIG(n, A);
            default:
                throw new Error('not implemented');
        }
    };

    Transaction.prototype.__sign_P2WSH_MULTISIG = function (n, A) {
        let scriptCode = BC([BF(S.intToVarInt(A.redeemScript.length)), A.redeemScript]);

        let sighash = this.sigHashSegwit(n, {scriptPubKey: scriptCode,
            sigHashType: A.sigHashType, value: A.value});
        sighash = getBuffer(sighash);
        let sig = [];
        this.vIn[n].signatures = [];
        for (let key of A.privateKey) {
            let s = BC([S.signMessage(sighash, key).signature,  BF(S.intToBytes(A.sigHashType, 1))]);
            sig.push(s);
            this.vIn[n].signatures.push((this.format === 'raw') ? s : s.hex());
        }

        let witness =  this.__get_MULTISIG_scriptSig(n, A.publicKey, sig, scriptCode, A.redeemScript, A.value);
        if (this.format === 'raw') this.vIn[n].txInWitness = witness;
        else {
            this.vIn[n].txInWitness = [];
            for (let w of witness) this.vIn[n].txInWitness.push(w.hex());
        }
        return BF([]);
    };

    Transaction.prototype.__sign_MULTISIG = function (n, A) {
        let sighash = this.sigHash(n, {scriptPubKey: A.scriptPubKey, sigHashType: A.sigHashType});
        if (iS(sighash)) sighash = s2rh(sighash);
        let sig = [];
        this.vIn[n].signatures = [];
        for (let key of A.privateKey) {
            let s = BC([S.signMessage(sighash, key).signature,  BF(S.intToBytes(A.sigHashType, 1))]);
            sig.push(s);
            this.vIn[n].signatures.push((this.format === 'raw') ? s : s.hex());
        }
        return this.__get_bare_multisig_script_sig__(n, A.publicKey,
            sig, A.scriptPubKey);
    };

    Transaction.prototype.__get_bare_multisig_script_sig__ = function (n, publicKeys, signatures, scriptPubKey) {
        let sigMap = {};
        for (let i in publicKeys)  sigMap[publicKeys[i]] = signatures[i];
        scriptPubKey.seek(0);
        let pubKeys = S.getMultiSigPublicKeys(scriptPubKey);
        let s = getBuffer(this.vIn[n].scriptSig);
        s.seek(0);
        let r = S.readOpCode(s);
        while (r[0] !== null) {
            r = S.readOpCode(s);
            if ((r[1] !== null) && S.isValidSignatureEncoding(r[1])) {
                let sigHash = this.sigHash(n, {scriptPubKey: scriptPubKey, sigHashType: r[1][r[1].length - 1]});
                if (iS(sigHash)) sigHash = s2rh(sigHash);
                for (let i =0; i<4; i++) {
                    let pk = S.publicKeyRecovery(r[1].slice(0, r[1].length - 1), sigHash, i,  {hex: false});
                    if (pk === null) continue;
                    for (let p of  pubKeys)
                        if (pk.equals(p)) {
                            sigMap[pk] = r[1];
                            break;
                        }
                }
            }
        }
        r =[BF([O.OP_0])];
        for (let p of pubKeys)
            if (sigMap[p] !== undefined) r.push(S.opPushData(sigMap[p]));
        return BC(r);
    };

    Transaction.prototype.__get_MULTISIG_scriptSig = function (n, publicKeys, signatures, scriptCode,
                                                               redeemScript, value = null) {
    let sigMap = {};
    for (let i in publicKeys)  sigMap[publicKeys[i]] = signatures[i];
    redeemScript.seek(0);
    let pubKeys = S.getMultiSigPublicKeys(redeemScript);
    let p2wsh = (value !== null);
    if (!p2wsh) {
        let s = getBuffer(this.vIn[n].scriptSig);
        s.seek(0);
        let r = S.readOpCode(s);
        while (r[0] !== null) {
            r = S.readOpCode(s);
            if ((r[1] !== null) && S.isValidSignatureEncoding(r[1])) {
                let sigHash = this.sigHash(n, {scriptPubKey: scriptCode, sigHashType: r[1][r[1].length - 1]});
                if (iS(sigHash)) sigHash = s2rh(sigHash);
                for (let i =0; i<4; i++) {
                    let pk = S.publicKeyRecovery(r[1].slice(0, r[1].length - 1), sigHash, i,  {hex: false});
                    if (pk === null) continue;
                    for (let p of  pubKeys)
                        if (pk.equals(p)) {
                            sigMap[pk] = r[1];
                            break;
                        }
                }
            }
        }
        r =[BF([O.OP_0])];
        for (let p of pubKeys)
            if (sigMap[p] !== undefined) r.push(S.opPushData(sigMap[p]));

        r.push(S.opPushData(redeemScript));
        return BC(r);
    }
    if (this.vIn[n].txInWitness !== undefined)
        for (let w of this.vIn[n].txInWitness) {
            w = getBuffer(w);
            if ((w.length > 0) && (S.isValidSignatureEncoding(w))) {
                let sigHash = this.sigHashSegwit(n, {scriptPubKey: scriptCode,
                    sigHashType: w[w.length - 1], value: value});
                sigHash = getBuffer(sigHash);
                for (let i =0; i<4; i++) {
                    let pk = S.publicKeyRecovery(w.slice(0, w.length - 1), sigHash, i,  {hex: false});
                    if (pk === null) continue;
                    for (let p of  pubKeys)
                        if (pk.equals(p)) {
                            sigMap[pk] = w;
                            break;
                        }
                }
            }
        }

    let r = [BF([])];
    for (let p of pubKeys)
        if (sigMap[p] !== undefined) r.push(sigMap[p]);
    r.push(redeemScript);
    return r;
};



    S.Transaction = Transaction;

};


