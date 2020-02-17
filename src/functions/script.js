module.exports = function (constants, hash, encoders, tools, opcodes, address) {
    let Buffer = tools.Buffer;
    let defArgs = tools.defArgs;
    let getBuffer = tools.getBuffer;
    let B = Buffer.from;
    let BC = Buffer.concat;
    let O = opcodes.OPCODE;
    let C = constants;
    let H = hash;
    return {
        hashToScript: (h, script_type, A = {}) => {
            defArgs(A, {hex: false});
            if (tools.isString(script_type)) script_type = C.SCRIPT_TYPES[script_type];
            h = getBuffer(h);
            let s;
            switch (script_type) {
                case 0:
                    s = BC([B([O.OP_DUP, O.OP_HASH160, 0x14]), h, B([O.OP_EQUALVERIFY, O.OP_CHECKSIG])]);
                    break;
                case 1:
                    s = BC([B([O.OP_HASH160, 0x14]), h, B([O.OP_EQUAL])]);
                    break;
                case 5:
                case 6:
                    s = BC([B([0, 0x14]), h]);
                    break;
                default:
                    throw new Error('unsupported script type');
            }
            return (A.hex) ? s.toString('hex') : s;
        },
        publicKeyTo_P2SH_P2WPKH_Script: (h, A = {}) => {
            defArgs(A, {hex: false});
            h = getBuffer(h);
            if (h.length !== 33) throw new Error("public key len invalid");
            let s = BC([B([0, 0x14]), hash.hash160(h)]);
            return (A.hex) ? s.toString('hex') : s;
        },
        publicKeyTo_PUBKEY_Script: (k, A = {}) => {
            defArgs(A, {hex: false});
            k = getBuffer(k);
            let s = BC([B([k.length]), k, B([O.OP_CHECKSIG])]);
            return (A.hex) ? s.toString('hex') : s;
        },
        parseScript: (s, A = {}) => {
            defArgs(A, {segwit: true});
            s = getBuffer(s);
            let l = s.length;
            if (l === 0)  return {nType: 7, type: "NON_STANDARD", reqSigs: 0, "script": s};

            if (A.segwit) {
                if ((l === 22)&&(s[0] === 0))
                    return {nType: 5, type: "P2WPKH", reqSigs: 1, addressHash: s.slice(2)};
                if ((l === 34)&&(s[0] === 0))
                    return {nType: 6, type: "P2WSH", reqSigs: NaN, addressHash: s.slice(2)};
            }

            if ((l === 25)&&(s[0]===0x76)&&(s[1]===0xa9)&&(s[l-2]===0x88)&&(s[l-1]===0xac))
                return {nType: 0, type: "P2PKH", reqSigs: 1, addressHash: s.slice(3,-2)};
            if ((l === 23)&&(s[0]===169)&&(s[l-1]===135))
                return {nType: 1, type: "P2SH", reqSigs: NaN, addressHash: s.slice(2,-1)};
            if (((l === 67)||(l === 35))&&(s[l-1]===172))
                return {nType: 2, type: "PUBKEY", reqSigs: 1, addressHash: H.hash160(s.slice(1,-1))};

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
                    q += 2 + s.b.readIntLE(q, 2);
                } else if  (s[q]===O.OP_PUSHDATA4) {
                    if (s[q + 3]===undefined) break;
                    q += 4 + s.b.readIntLE(q, 4);
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
        },
        scriptToAddress: function(s, A = {}) {
            defArgs(A, {testnet: false});
            s = this.parseScript(s);
            if (s.addressHash !== undefined) {
                let wv = ((s.nType===5)||(s.nType===6)) ? 0:NaN;
                let sh = ((s.nType===1)||(s.nType===6));
                return address.hashToAddress(s.addressHash, {testnet: A.testnet, script_hash: sh, witness_version: wv})
            }
            return NaN;
        }

    }
};