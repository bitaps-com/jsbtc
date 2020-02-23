module.exports = function (S) {
    let Buffer = S.Buffer;
    let ARGS = S.defArgs;
    let getBuffer = S.getBuffer;
    let BF = Buffer.from;
    let BC = Buffer.concat;
    let O = S.OPCODE;
    let RO = S.RAW_OPCODE;
    let CM = S.__bitcoin_core_crypto.module;;
    let malloc = CM._malloc, free = CM._free, getValue = CM.getValue;

    S.hashToScript = (h, scriptType, A = {}) => {
            ARGS(A, {hex: false});
            if (S.isString(scriptType)) scriptType = S.SCRIPT_TYPES[scriptType];
            h = getBuffer(h);
            let s;
            switch (scriptType) {
                case 0:
                    s = BC([BF([O.OP_DUP, O.OP_HASH160, 0x14]), h, BF([O.OP_EQUALVERIFY, O.OP_CHECKSIG])]);
                    break;
                case 1:
                    s = BC([BF([O.OP_HASH160, 0x14]), h, BF([O.OP_EQUAL])]);
                    break;
                case 5:
                case 6:
                    s = BC([BF([0, 0x14]), h]);
                    break;
                default:
                    throw new Error('unsupported script type');
            }
            return (A.hex) ? s.hex() : s;
        };

    S.publicKeyTo_P2SH_P2WPKH_Script = (h, A = {}) => {
            ARGS(A, {hex: false});
            h = getBuffer(h);
            if (h.length !== 33) throw new Error("public key len invalid");
            let s = BC([BF([0, 0x14]), S.hash160(h)]);
            return (A.hex) ? s.hex() : s;
        };

    S.publicKeyTo_PUBKEY_Script = (k, A = {}) => {
            ARGS(A, {hex: false});
            k = getBuffer(k);
            let s = BC([BF([k.length]), k, BF([O.OP_CHECKSIG])]);
            return (A.hex) ? s.hex() : s;
        };

    S. parseScript = (s, A = {}) => {
            ARGS(A, {segwit: true});
            s = getBuffer(s);
            let l = s.length;
            if (l === 0)  return {nType: 7, type: "NON_STANDARD", reqSigs: 0, "script": s};
            if (A.segwit) {
                if ((l === 22)&&(s[0] === 0))
                    return {nType: 5, type: "P2WPKH", reqSigs: 1, addressHash: s.slice(2)};
                if ((l === 34)&&(s[0] === 0))
                    return {nType: 6, type: "P2WSH", reqSigs: null, addressHash: s.slice(2)};
            }

            if ((l === 25)&&(s[0]===0x76)&&(s[1]===0xa9)&&(s[l-2]===0x88)&&(s[l-1]===0xac))
                return {nType: 0, type: "P2PKH", reqSigs: 1, addressHash: s.slice(3,-2)};
            if ((l === 23)&&(s[0]===169)&&(s[l-1]===135))
                return {nType: 1, type: "P2SH", reqSigs: null, addressHash: s.slice(2,-1)};
            if (((l === 67)||(l === 35))&&(s[l-1]===172))
                return {nType: 2, type: "PUBKEY", reqSigs: 1, addressHash: S.hash160(s.slice(1,-1))};

            if (s[0] === O.OP_RETURN) {
                if (l===1) return {nType: 3, type: "NULL_DATA", reqSigs: 0, "data": s.slice(1)};
                if ((s[1] < O.OP_PUSHDATA1)&&(s[1]===l-2))
                    return {nType: 3, type: "NULL_DATA", reqSigs: 0, "data": s.slice(2)};
                if ((s[1] === O.OP_PUSHDATA1)&&(l>2)&&(s[2]===l-3)&&(s[2]<=80))
                    return {nType: 3, type: "NULL_DATA", reqSigs: 0, "data": s.slice(3)};
                return {nType: 8, type: "NULL_DATA_NON_STANDARD", reqSigs: 0, "script": s}
            }

            if ((s[0]>=81)&&(s[0]<=96)&&(s[l-1]===174)&&(s[l-2]>=81)&&(s[l-2]<=96)&&(s[l-2]>=s[0])) {
                let c=0, q=1;
                while (l-q-2  > 0) {
                    if (s[q]<0x4c) {
                        q += s[q];
                        c++;
                    } else {
                        q = 0;
                        break;
                    }
                    q++;
                }
                if (c === s[l-2] - 80)
                    return {nType: 4, type: "MULTISIG", reqSigs: s[0] - 80, "pubKeys": c, "script": s}
            }

            let q=0,m=0,n=0,last=0,r=0;
            while (l-q > 0) {
                if ((s[q]>=81)&&(s[q]<=96)) {
                    if (!n) n = s[q] - 80;
                    else {
                        if ((m===0)||(m>n)) {
                            n = s[q] - 80;
                            m = 0;
                        } else if (m===s[q]-80) last = (last) ? 0:2;
                    }
                } else if (s[q]<0x4c) {
                    q+=s[q];
                    m++;
                    if (m>16) {
                        m=0;
                        n=0;
                    }
                } else if (s[q]===O.OP_PUSHDATA1) {
                    if (s[q + 1]===undefined) break;
                    q += 1 + s[q + 1];
                } else if  (s[q]===O.OP_PUSHDATA2) {
                    if (s[q + 1]===undefined) break;
                    q += 2 + s.readIntLE(q, 2);
                } else if  (s[q]===O.OP_PUSHDATA4) {
                    if (s[q + 3]===undefined) break;
                    q += 4 + s.readIntLE(q, 4);
                } else {
                    if (s[q]===O.OP_CHECKSIG) r++;
                    else if (s[q]===O.OP_CHECKSIGVERIFY) r++;
                    else if ([O.OP_CHECKMULTISIG, O.OP_CHECKMULTISIGVERIFY].includes(s[q])) {
                        if (last) r+=n;
                        else r += 20;
                    }
                    n = 0;
                    m = 0;
                }
                if (last) last--;
                q++;
            }
            return {nType: 7, type: "NON_STANDARD", reqSigs: r, "script": s}
        };

        S.scriptToAddress = (s, A = {}) => {
            ARGS(A, {testnet: false});
            s = S.parseScript(s);
            if (s.addressHash !== undefined) {
                let wv = ((s.nType===5)||(s.nType===6)) ? 0:null;
                let sh = ((s.nType===1)||(s.nType===6));
                return S.hashToAddress(s.addressHash, {testnet: A.testnet, scriptHash: sh, witnessVersion: wv})
            }
            return null;
        };

        S.decodeScript = (s, A = {}) => {
            ARGS(A, {asm: false});
            s = getBuffer(s);
            let l = s.length, q = 0, result = [];
            if (l===0) return '';
            try{
                while (l-q>0) {
                    if ((s[q]<0x4c)&&(s[q])) {
                        if (A.asm) {
                            result.push(`OP_PUSHBYTES[${s[q]}]`);
                            result.push(s.slice(q+1, q+1+s[q]).hex());
                        } else result.push(`[${s[q]}]`);
                        q += s[q]+1;
                        continue;
                    }
                    if (s[q] === O.OP_PUSHDATA1) {
                        if (A.asm) {
                            result.push(`OP_PUSHDATA1[${s[q+1]}]`);
                            result.push(s.slice(q+2, q+2+s[q+1]).hex());
                        } else {
                            result.push(RO[s[q]]);
                            result.push(`[${s[q+1]}]`);
                        }
                        q+=1+s[q+1]+1;
                        continue;
                    }
                    if (s[q] === O.OP_PUSHDATA2) {
                        let w = s.readIntLE(q + 1, 2);
                        if (A.asm) {
                            result.push(`OP_PUSHDATA2[${w}]`);
                            result.push(s.slice(q+3, q+3+w).hex());
                        } else {
                            result.push(RO[s[q]]);
                            result.push(`[${s[w]}]`);
                        }
                        q+=w+3;
                        continue;
                    }
                    if (s[q] === O.OP_PUSHDATA4) {
                        let w = s.readIntLE(q + 1, 4);
                        if (A.asm) {
                            result.push(`OP_PUSHDATA4[${w}]`);
                            result.push(s.slice(q+5, q+5+w).hex());
                        } else {
                            result.push(RO[s[q]]);
                            result.push(`[${s[w]}]`);
                        }
                        q+=w+6;
                        continue;
                    }
                    result.push(RO[s[q]]);
                    q++;
                }
            } catch (e) {
                result.push("[SCRIPT_DECODE_FAILED]");
            }
            return result.join(' ');
        };

        S.deleteFromScript = (script, subScript, A = {}) => {
            ARGS(A, {hex: false});
            if (subScript === undefined) return script;
            if (subScript.length === 0) return script;
            let s = getBuffer(script);
            let s2 = getBuffer(subScript);
            let l = s.length, ls = s2.length;
            let q = 0, k = 0, stack = [], result = []
            while (l-q>0) {
                if ((s[q]<0x4c)&&(s[q])) {
                    stack.push(s[q]+1);
                    q+=s[q]+1;
                }
                else if (s[q] === O.OP_PUSHDATA1) {
                    stack.push(1+s[q+1]);
                    q+=1+s[q+1];
                }
                else if  (s[q] === O.OP_PUSHDATA2) {
                    let w = s.readIntLE(q, 2);
                    stack.push(2+w);
                    q+=2+w;
                }
                else if  (s[q] === O.OP_PUSHDATA4) {
                    let w = s.readIntLE(q, 4);
                    stack.push(4+w);
                    q+=4+w;
                }
                else {
                    stack.push(1);
                    q+=1
                }

                if (q-k >= ls) {
                    if (s.slice(k,q).slice(0,ls).equals(s2)) {
                        if (q-k>ls) result.push(s.slice(k+ls,q));
                        let t = 0;
                        while (t!==q-k) t+=stack.shift();
                        k = q;
                    }
                    else {
                        let t = stack.shift();
                        result.push(s.slice(k, k + t));
                        k += t;
                    }
                }
            }

            if (s.slice(k,q).slice(0,ls).equals(s2)) {
                if (q - k > ls) result.push(s.slice(k+ls,q));
            }
            else result.push(s.slice(k,k+ls));

            let out = BC(result);
            return (A.hex)? out.hex(): out;
        };

        S.scriptToHash = (s, A = {}) => {
            ARGS(A, {witness: false, hex: true});
            return (A.witness) ? S.sha256(s, A) : S.hash160(s, A)
            };

        S.opPushData = (s) => {
           if (s.length <= 0x4b) return BC([BF([s.length]), s]);
           if (s.length <= 0xff) return BC([BF([O.OP_PUSHDATA1, s.length]), s]);
           if (s.length <= 0xffff) return BC([BF([O.OP_PUSHDATA2].concat(S.intToBytes(s.length, 2, 'little'))), s]);
           return BC([BF([O.OP_PUSHDATA4].concat(S.intToBytes(s.length, 4, 'little'))), s]);
        };

        S.readOpcode = (s) => {
            let b = s.read(1);
            if (!b.length) return [null,null];
            if (b[0] <= 0x4b) return [b, s.read(b[0])];
            if (b[0] === O.OP_PUSHDATA1) return [b, s.read(s.read(1)[0])];
            if (b[0] === O.OP_PUSHDATA2) return [b, s.read(s.read(2).readIntLE(0, 2))];
            if (b[0] === O.OP_PUSHDATA4) return [b, s.read(s.read(4).readIntLE(0, 4))];
            return [b, null]
        };

        S.signMessage = (m, privateKey, A = {}) => {
            ARGS(A, {encoding: 'hex|utf8', hex: false});
            m = getBuffer(m, A.encoding);
            if (S.isString(privateKey)) {
                if (S.isHex(privateKey)) privateKey = BF(privateKey, 'hex');
                else if (key.isWifValid(m)) privateKey = key.wifToPrivateKey(m, {hex: false});
                else throw new Error("private key invalid");
            }
            else if (!Buffer.isBuffer(m)) privateKey = BF(m);
            if (privateKey.length !== 32) throw new Error("private key length invalid");
            if (m.length !== 32) throw new Error("message length invalid");

            let mP, pP, sP, len, signature,sDp,  r = 0, recId;
            try {
                mP = malloc(32);
                pP = malloc(32);
                sP = malloc(65);
                sDp = malloc(72);
                len = malloc(1);
                CM.HEAPU8.set(m, mP);
                CM.HEAPU8.set(privateKey, pP);
                r = CM._secp256k1_ecdsa_sign_recoverable(S.secp256k1PrecompContextSign, sP, mP, pP, null, null);
                if (r) {
                    recId = getValue(sP + 64, 'i8');
                    r = CM._secp256k1_ecdsa_signature_serialize_der(S.secp256k1PrecompContextSign, sDp, len, sP)
                    if (r) {
                        let l = getValue(len, 'i8');
                        signature = new Buffer.alloc(l);
                        for (let i=0; i<l; i++) signature[i] = getValue(sDp + i, 'i8');
                    }
                }


            } finally {
                free(mP);
                free(pP);
                free(sP);
                free(sDp);
                free(len);
            }

            if (r) {
                return {
                    signature: (A.hex) ? signature.hex() : signature,
                    recId: recId
                }
            }
            return null;
        };

        S.verifySignature = (s, p, m) => {
            s = getBuffer(s);
            p = getBuffer(p);
            m = getBuffer(m);
            let mP, pP, sP, sCp, pCp,  r = 0;
            try {
                mP = malloc(m.length);
                pP = malloc(p.length);
                sP = malloc(s.length);
                sCp = malloc(64);
                pCp = malloc(65);
                CM.HEAPU8.set(m, mP);
                CM.HEAPU8.set(p, pP);
                CM.HEAPU8.set(s, sP);
                r = CM._secp256k1_ecdsa_signature_parse_der(S.secp256k1PrecompContextSign, sCp, sP, s.length);
                if (r) {
                    r = CM._secp256k1_ec_pubkey_parse(S.secp256k1PrecompContextVerify, pCp, pP, p.length);
                    if (r) {
                        r = CM._secp256k1_ecdsa_verify(S.secp256k1PrecompContextVerify, sCp, mP, pCp);
                    }
                }
            }
            finally {
                free(mP);
                free(pP);
                free(sP);
                free(sCp);
            }
            return Boolean(r);
        };

        S.publicKeyRecovery = (s, m, recId, A = {}) => {
            ARGS(A, {compressed: true, hex: true});
            s = getBuffer(s);
            m = getBuffer(m);

            let mP, sCp, sP,sCcP, sCcRp, lP, sPub, pub, out, r = 0, len,flag;
            try {
                mP = malloc(m.length);
                sP = malloc(s.length);
                sCp = malloc(64);
                sCcP = malloc(64);
                sCcRp = malloc(65);
                pub = malloc(65);
                sPub = malloc(65);
                lP = malloc(1);
                CM.HEAPU8.set(m, mP);
                CM.HEAPU8.set(s, sP);
                r = CM._secp256k1_ecdsa_signature_parse_der(S.secp256k1PrecompContextSign, sCp, sP, s.length);
                if (r) r = CM._secp256k1_ecdsa_signature_serialize_compact(S.secp256k1PrecompContextSign, sCcP, sCp);
                if (r) r = CM._secp256k1_ecdsa_recoverable_signature_parse_compact(S.secp256k1PrecompContextSign, sCcRp, sCcP, recId);
                if (r) r = CM._secp256k1_ecdsa_recover(S.secp256k1PrecompContextVerify, pub, sCcRp, mP);
                if (r) {
                    if (A.compressed) {
                        len = 33;
                        flag = S.SECP256K1_EC_COMPRESSED;
                    } else {
                        len = 65;
                        flag = S.SECP256K1_EC_UNCOMPRESSED;
                    }
                    CM.HEAP8.set([len], lP);
                    r = CM._secp256k1_ec_pubkey_serialize(S.secp256k1PrecompContextVerify, sPub, lP, pub, flag);
                }
                if (r) {
                    out = new Buffer.alloc(len);
                    for (let i=0; i<len; i++) out[i] = getValue(sPub + i, 'i8');
                }
            } finally {
                free(mP);
                free(sP);
                free(sCp);
                free(sCcP);
                free(sCcRp);
                free(pub);
                free(sPub);
                free(lP);
            }

            if (r) return (A.hex)? out.hex(): out;
            return null;
        };

        S.isValidSignatureEncoding = (s) => {
            // # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
            // # * total-length: 1-byte length descriptor of everything that follows,
            //     #   excluding the sighash byte.
            //     # * R-length: 1-byte length descriptor of the R value that follows.
            //     # * R: arbitrary-length big-endian encoded R value. It must use the shortest
            // #   possible encoding for a positive integers (which means no null bytes at
            // #   the start, except a single one when the next byte has its highest bit set).
            // # * S-length: 1-byte length descriptor of the S value that follows.
            //     # * S: arbitrary-length big-endian encoded S value. The same rules apply.
            //     # * sighash: 1-byte value indicating what data is hashed (not part of the DER
            // #   signature)
            s = getBuffer(s);
            let l = s.length;
            if (((l<9)||(l>73)) || (s[0]!==0x30) || (s[1]!==l-3))return false;
            let lR = s[3];
            if (5+lR>=l) return false;
            let lS = s[5+lR];
            if (((lR + lS + 7)!==l) || (s[2]!==0x02) || (lR===0) || (s[4]===0x80)) return false;
            if (((lR>1)&&(s[4]===0)&&(!(s[5]&0x80))) || (s[lR+4]!==0x02) || (lS===0) || (s[lR+6]&0x80)) return false;
            return !((lS > 1) && (s[lR + 6] === 0) && (!(s[lR + 7] & 0x80)));

        };

        S.parseSignature = function (s, A = {}) {
            // # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
            // # * total-length: 1-byte length descriptor of everything that follows,
            //     #   excluding the sighash byte.
            //     # * R-length: 1-byte length descriptor of the R value that follows.
            //     # * R: arbitrary-length big-endian encoded R value. It must use the shortest
            // #   possible encoding for a positive integers (which means no null bytes at
            // #   the start, except a single one when the next byte has its highest bit set).
            // # * S-length: 1-byte length descriptor of the S value that follows.
            //     # * S: arbitrary-length big-endian encoded S value. The same rules apply.
            //     # * sighash: 1-byte value indicating what data is hashed (not part of the DER
            // #   signature)
            ARGS(A, {hex: false});
            s = getBuffer(s);
            let l = s.length;
            if (!this.isValidSignatureEncoding(s))  throw new Error('invalid signature');
            let lR = s[3];
            let r = s.slice(5, 4+ lR);
            let lS = s[5 + lR];
            s = s.slice(lR + 6, lS);
            return [(A.hex)?r.hex():r, (A.hex)?s.hex():s];
        };
};