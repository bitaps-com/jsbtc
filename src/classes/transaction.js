module.exports = function (constants, hash, encoders, tools, opcodes, address, key, script) {
    let T = tools;
    let s2rh = tools.s2rh;
    let rh2s = tools.rh2s;
    let Buffer = T.Buffer;
    let BN = T.BN;
    let isBuffer = T.Buffer.isBuffer;
    let defArgs = T.defArgs;
    let getBuffer = T.getBuffer;
    let B = Buffer.from;
    let BC = Buffer.concat;
    let O = opcodes.OPCODE;
    let C = constants;
    let iS = tools.isString;

    class Transaction {
        constructor(A = {}) {
            defArgs(A, {
                raw_tx: null, format: 'decoded', version: 1,
                lock_time: 0, testnet: false, auto_commit: true, keep_raw_tx: false
            });
            if (!["decoded", "raw"].includes(A.format)) throw new Error('format error, raw or decoded allowed');
            this.autoCommit = A.auto_commit;
            this.format = A.format;
            this.testnet = A.testnet;
            this.segwit = A.segwit;
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
            if (A.raw_tx === null) return;
            let tx = getBuffer(A.raw_tx);
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
            let ic = T.varIntToInt(n);
            for (let k = 0; k < ic; k++)
                this.vIn[k] = {
                    txId: tx.read(32),
                    vOut: tx.readInt(4),
                    scriptSig: tx.read(T.varIntToInt(tx.readVarInt())),
                    sequence: tx.readInt(4)
                };
            // outputs
            let oc = T.varIntToInt(tx.readVarInt());
            for (let k = 0; k < oc; k++) {
                this.vOut[k] = {};
                this.vOut[k].value = tx.readInt(8);
                this.amount += this.vOut[k].value;
                this.vOut[k].scriptPubKey = tx.read(T.varIntToInt(tx.readVarInt()));
                let s = script.parseScript(this.vOut[k].scriptPubKey);
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
                    let t = T.varIntToInt(tx.readVarInt());
                    for (let q = 0; q < t; q++)
                        this.vIn[k].txInWitness.push(tx.read(T.varIntToInt(tx.readVarInt())));
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
                this.hash = hash.doubleSha256(this.rawTx);
                this.txId = hash.doubleSha256(BC([this.rawTx.slice(0, 4),
                    this.rawTx.slice(6, sw), this.rawTx.slice(this.rawTx.length - 4, this.rawTx.length)]));
            } else {
                this.txId = hash.doubleSha256(this.rawTx);
                this.hash = this.txId;
                this.segwit = false;
            }
            if (!A.keep_raw_tx) this.rawTx = null;
            if (A.format == 'decoded') this.decode();
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
            if (this.vIn[i].amount instanceof tools.BN) this.vIn[i].amount = this.vIn[i].amount.toString(16);
            if (this.vIn[i].txInWitness !== undefined) {
                let t = [];
                for (let w of this.vIn[i].txInWitness) t.push((isBuffer(w) ? w.hex() : w));
                this.vIn[i].txInWitness = t;
            }
            if (isBuffer(this.vIn[i].addressHash)) {
                let w = (this.vIn[i].nType < 5) ? null : this.vIn[i].addressHash[0];
                this.vIn[i].addressHash = this.vIn[i].addressHash.hex();
                let sh = [1, 5].includes(this.vIn[i].nType);
                this.vIn[i].address = address.hashToAddress(this.vIn[i].addressHash,
                    {testnet: this.testnet, script_hash: sh, witness_version: w});

            }
            if (isBuffer(this.vIn[i].scriptPubKey)) {
                this.vIn[i].scriptPubKey = this.vIn[i].scriptPubKey.hex();
                this.vIn[i].scriptPubKeyOpcodes = script.decodeScript(this.vIn[i].scriptPubKey);
                this.vIn[i].scriptPubKeyAsm = script.decodeScript(this.vIn[i].scriptPubKey, {asm: true});
            }
            if (isBuffer(this.vIn[i].redeemScript)) {
                this.vIn[i].redeemScript = this.vIn[i].redeemScript.hex();
                this.vIn[i].redeemScriptOpcodes = script.decodeScript(this.vIn[i].redeemScript);
                this.vIn[i].redeemScriptAsm = script.decodeScript(this.vIn[i].redeemScript, {asm: true});
            }
            if (!this.coinbase) {
                if (isBuffer(this.vIn[i].scriptSig)) {
                    this.vIn[i].scriptSig = this.vIn[i].scriptSig.hex();
                }

                this.vIn[i].scriptSigOpcodes = script.decodeScript(this.vIn[i].scriptSig);
                this.vIn[i].scriptSigAsm = script.decodeScript(this.vIn[i].scriptSig, {asm: true});
            }
        }

        for (let i in this.vOut) {
            if (isBuffer(this.vOut[i].addressHash)) {
                let w = (this.vOut[i].nType < 5) ? null : this.vOut[i].addressHash[0];
                this.vOut[i].addressHash[0];
                this.vOut[i].addressHash = this.vOut[i].addressHash.hex();
                let sh = [1, 5].includes(this.vOut[i].nType);
                this.vOut[i].address = address.hashToAddress(this.vOut[i].addressHash,
                    {testnet: this.testnet, script_hash: sh, witness_version: w});

            }
            if (isBuffer(this.vOut[i].scriptPubKey)) {
                this.vOut[i].scriptPubKey = this.vOut[i].scriptPubKey.hex();
                this.vOut[i].scriptPubKeyOpcodes = script.decodeScript(this.vOut[i].scriptPubKey);
                this.vOut[i].scriptPubKeyAsm = script.decodeScript(this.vOut[i].scriptPubKey, {asm: true});
            }



        }
        if (isBuffer(this.data)) this.data = this.data.hex();

    };


    Transaction.prototype.encode = function () {
        if  (iS(this.txId)) this.txId = s2rh(this.txId);
        if  (iS(this.flag)) this.flag = s2rh(this.flag);
        if  (iS(this.hash)) this.hash = s2rh(this.hash);
        if  (iS(this.rawTx)) this.rawTx = B(this.hash, 'hex');
        for (let i in this.vIn) {
            if (iS(this.vIn[i].txId)) this.vIn[i].txId = s2rh(this.vIn[i].txId);
            if (iS(this.vIn[i].scriptSig)) this.vIn[i].scriptSig = B(this.vIn[i].scriptSig, 'hex');
            if (this.vIn[i].txInWitness !== undefined) {
                let t = [];
                for (let w of this.vIn[i].txInWitness) t.push((iS(w) ? B(w, 'hex') : w));
                this.vIn[i].txInWitness = t;
            }
            if (iS(this.vIn[i].addressHash)) this.vIn[i].addressHash = B(this.vIn[i].addressHash, 'hex');
            if (iS(this.vIn[i].scriptPubKey)) this.vIn[i].scriptPubKey = B(this.vIn[i].scriptPubKey, 'hex');
            if (iS(this.vIn[i].redeemScript)) this.vIn[i].redeemScript = B(this.vIn[i].redeemScript, 'hex');
            if (iS(this.vIn[i].addressHash)) this.vIn[i].addressHash = B(this.vIn[i].addressHash, 'hex');
            delete this.vIn[i].scriptSigAsm;
            delete this.vIn[i].scriptSigOpcodes;
            delete this.vIn[i].scriptPubKeyOpcodes;
            delete this.vIn[i].scriptPubKeyAsm;
            delete this.vIn[i].redeemScriptOpcodes;
            delete this.vIn[i].redeemScriptAsm;
            delete this.vIn[i].address;
        }
        for (let i in this.vOut) {
            if (iS(this.vOut[i].scriptPubKey)) this.vOut[i].scriptPubKey = B(this.vOut[i].scriptPubKey, 'hex');
            if (iS(this.vOut[i].addressHash)) this.vOut[i].addressHash = B(this.vOut[i].addressHash, 'hex');
            delete this.address;
            delete this.vIn[i].scriptPubKeyOpcodes;
            delete this.vIn[i].scriptPubKeyAsm;
        }
        if (iS(this.data)) this.data = B(this.data, 'hex');
        this.format = 'raw';
    };

    Transaction.prototype.serialize = function (A = {}) {
        defArgs(A, {segwit: true, hex: true});
        let chunks = [];
        chunks.push(B(T.intToBytes(this.version, 4)));
        if (A.segwit&&this.segwit) chunks.push(B([0,1]));
        chunks.push(B(T.intToVarInt(Object.keys(this.vIn).length)));

        for (let i in this.vIn) {
            if (iS(this.vIn[i].txId)) chunks.push(s2rh(this.vIn[i].txId));
            else chunks.push(this.vIn[i].txId);
            chunks.push(B(T.intToBytes(this.vIn[i].vOut, 4)));
            let s = (iS(this.vIn[i].scriptSig))? B(this.vIn[i].scriptSig, 'hex'):this.vIn[i].scriptSig;

            chunks.push(B(T.intToVarInt(s.length)));
            chunks.push(s);
            chunks.push(B(T.intToBytes(this.vIn[i].sequence, 4)));
            }
        chunks.push(B(T.intToVarInt(Object.keys(this.vOut).length)));

        for (let i in this.vOut) {
            chunks.push(B(T.intToBytes(this.vOut[i].value, 8)));
            let s = (iS(this.vOut[i].scriptPubKey))? B(this.vOut[i].scriptPubKey, 'hex'):this.vOut[i].scriptPubKey;
            chunks.push(B(T.intToVarInt(s.length)));
            chunks.push(s);
        }
        if (A.segwit&&this.segwit) {
            for (let i in this.vIn) {
                chunks.push(B(T.intToVarInt(this.vIn[i].txInWitness.length)));
                for (let w of this.vIn[i].txInWitness) {
                    let s = iS(w)? B(w, 'hex'): w;
                    chunks.push(B(T.intToVarInt(s.length)));
                    chunks.push(s);
                }
            }
        }
        chunks.push(B(T.intToBytes(this.lockTime, 4)));
        let out = BC(chunks);
        return (A.hex)? out.hex(): out;
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
        defArgs(A, {tx_id: null, v_out: 0, sequence: 0xffffffff,
            script_sig: null, tx_in_witness: null, amount: null,
            script_pub_key: null, address: null, private_key: null,
            redeem_script: null, input_verify: true});
        let witness = [], script;
        if (A.tx_id === null) {
            A.tx_id = Buffer(32);
            A.v_out = 0xffffffff;
            if (((A.sequence !== 0xffffffff)||(Object.keys(this.vOut).length))&&(A.input_verify))
                throw new Error('invalid coinbase transaction');
        }
        if (iS(A.tx_id))
            if (T.isHex(A.tx_id)) A.tx_id = B(A.tx_id, 'hex');
            else  throw new Error('tx_id invalid');
        if (!isBuffer(A.tx_id)||A.tx_id.length !== 32) throw new Error('tx_id invalid');

        if (iS(A.script_sig))
            if (T.isHex(A.script_sig)) A.script_sig = B(A.script_sig, 'hex');
            else  throw new Error('script_sig invalid');
        if (!isBuffer(A.script_sig)||((A.script_sig.length > 520)&&(A.input_verify)))
            throw new Error('script_sig invalid');

        if ((A.v_out<0)||A.v_out>0xffffffff) throw new Error('v_out invalid');
        if ((A.sequence<0)||A.sequence>0xffffffff) throw new Error('v_out invalid');

        if ((A.private_key !== null)&&(!(A.private_key instanceof address.PrivateKey)))
            A.private_key = address.PrivateKey(A.private_key);

        if ((A.amount!==null)&&((A.amount < 0)||(A.amount > MAX_AMOUNT)))
            throw new Error('amount invalid');

        if (A.tx_in_witness !== null) {
            let l = 0;
            for (let w of A.tx_in_witness) {
                if (iS(w)) witness.push((this.format==='raw')?B(w,'hex'):w);
                else witness.push((this.format==='raw')?w:B(w,'hex'));
                l+= 1+w.length;
            }
        }

        if (A.tx_id.equal(B(32))) {
            if (!((A.v_out === 0xffffffff)&&(A.sequence === 0xffffffff)&&(A.script_sig.length <= 100)))
                if (A.input_verify) throw new Error("coinbase tx invalid");
            this.coinbase = true;
        }

        if (A.script_pub_key !== null) {
            if (iS(A.script_pub_key)) A.script_pub_key = B(A.script_pub_key, 'hex');
            if (!isBuffer(A.script_pub_key)) throw new Error("script_pub_key invalid");
        }

        if (A.redeem_script !== null) {
            if (iS(A.redeem_script)) A.redeem_script = B(A.redeem_script, 'hex');
            if (!isBuffer(A.redeem_script)) throw new Error("script_pub_key invalid");
        }

        if (A.address !== null) {
            if (iS(A.address)) {
                let net = address.addressNetType(A.address) === 'mainnet';
                if (!(net !== this.testnet)) throw new Error("address invalid");
                script = address.addressToScript(A.address);
            } else if (A.address.address !== undefined) script = address.addressToScript(A.address.address);
            else throw new Error("address invalid");
            if (A.script_pub_key !== undefined) {
                if (!A.script_pub_key.equals(script)) throw new Error("address not match script");
            } else A.script_pub_key = script;

        }

        let k = Object.keys(this.vOut).length;


    };


    return {
        Transaction: Transaction
    }

};


