module.exports = function (constants, hash, encoders, tools, opcodes) {
    let Buffer = tools.Buffer;
    let defArgs = tools.defArgs;
    let getBuffer = tools.getBuffer;
    let B = Buffer.from;
    let BC = Buffer.concat;
    let O = opcodes.OPCODE;
    let C = constants;
    return {
        hashToAddress: (ha, A = {}) => {
            defArgs(A, {testnet: false, script_hash: false, witness_version: 0});
            ha = getBuffer(ha);
            let prefix;
            if (!A.script_hash) {
                if (isNaN(A.witness_version)) {
                    if (ha.length !== 20) throw new Error('address hash length incorrect');
                    if (A.testnet) prefix = B(C.TESTNET_ADDRESS_BYTE_PREFIX);
                    else prefix = B(C.MAINNET_ADDRESS_BYTE_PREFIX);
                    let h = BC([prefix, ha]);
                    h = BC([h, hash.doubleSha256(h, {hex: false}).slice(0, 4)]);
                    return encoders.encodeBase58(h);
                } else {
                    if ((ha.length !== 20) && (ha.length !== 32)) throw new Error('address hash length incorrect');
                }
            }

            if (isNaN(A.witness_version)) {
                if (A.testnet) prefix = B(C.TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX);
                else prefix = B(C.MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX);
                let h = BC([prefix, ha]);
                h = BC([h, hash.doubleSha256(h, {hex: false}).slice(0, 4)]);
                return encoders.encodeBase58(h);
            }

            let hrp;
            if (A.testnet) {
                prefix = C.TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                hrp = C.TESTNET_SEGWIT_ADDRESS_PREFIX;
            } else {
                prefix = C.MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                hrp = C.MAINNET_SEGWIT_ADDRESS_PREFIX;
            }
            ha = encoders.rebase_8_to_5(Array.from(ha));
            ha.unshift(A.witness_version);

            let checksum = encoders.bech32Polymod(prefix.concat(ha.concat([0, 0, 0, 0, 0, 0])));
            checksum = encoders.rebase_8_to_5(tools.intToBytes(checksum, 5)).slice(2);
            return hrp + '1' + encoders.rebase_5_to_32(ha.concat(checksum), false);
        },
        addressToHash: (a, A = {}) => {
            defArgs(A, {hex: false});
            if (!tools.isString(a)) throw new Error('address invalid');
            let h;
            if (C.ADDRESS_PREFIX_LIST.includes(a[0])) {
                h = encoders.decodeBase58(a, {hex: false});
                h = h.slice(1, h.length - 4);
            } else if ([C.MAINNET_SEGWIT_ADDRESS_PREFIX,
                C.TESTNET_SEGWIT_ADDRESS_PREFIX].includes(a.split('1')[0])) {
                let q = encoders.rebase_32_to_5(a.split('1')[1]);
                h = encoders.rebase_5_to_8(q.slice(1, q.length - 6), false);
                h = B(h);
            } else return NaN;
            return (A.hex) ? h.toString('hex') : h;
        },
        publicKeyToAddress: function (pubkey, A = {}) {
            defArgs(A, {testnet: false, p2sh_p2wpkh: false, witness_version: 0});
            pubkey = getBuffer(pubkey);
            let h;
            if (A.p2sh_p2wpkh) {
                if (pubkey.length !== 33) throw new Error('public key length invalid');
                h = hash.hash160(BC([B([0, 20]), hash.hash160(pubkey)]));
                A.witness_version = NaN
            } else {
                if (!isNaN(A.witness_version))
                    if (pubkey.length !== 33) throw new Error('public key length invalid');
                h = hash.hash160(pubkey);
            }
            A.script_hash = A.p2sh_p2wpkh;
            return this.hashToAddress(h, A);
        },
        addressType: (a, A = {}) => {
            defArgs(A, {num: false});
            if ([C.TESTNET_SCRIPT_ADDRESS_PREFIX, C.MAINNET_SCRIPT_ADDRESS_PREFIX].includes(a[0]))
                return (A.num) ? C.SCRIPT_TYPES["P2SH"] : "P2SH";
            if ([C.MAINNET_ADDRESS_PREFIX, C.TESTNET_ADDRESS_PREFIX, C.TESTNET_ADDRESS_PREFIX_2].includes(a[0]))
                return (A.num) ? C.SCRIPT_TYPES["P2PKH"] : "P2PKH";
            if ([C.MAINNET_SEGWIT_ADDRESS_PREFIX, C.TESTNET_SEGWIT_ADDRESS_PREFIX].includes(a.slice(0, 2))) {
                if (a.length === 42) return (A.num) ? C.SCRIPT_TYPES["P2WPKH"] : "P2WPKH";
                if (a.length === 62) return (A.num) ? C.SCRIPT_TYPES["P2WSH"] : "P2WSH";}
            return (A.num) ? C.SCRIPT_TYPES["NON_STANDARD"] : "NON_STANDARD";
        },
        addressNetType: (a) => {
            if ([C.MAINNET_SCRIPT_ADDRESS_PREFIX, C.MAINNET_ADDRESS_PREFIX].includes(a[0])) return "mainnet";
            if (a.slice(0, 2) === C.MAINNET_SEGWIT_ADDRESS_PREFIX) return "mainnet";
            if ([C.TESTNET_SCRIPT_ADDRESS_PREFIX, C.TESTNET_ADDRESS_PREFIX, C.TESTNET_ADDRESS_PREFIX_2].includes(a[0])) return "testnet";
            if (a.slice(0, 2) === C.TESTNET_SEGWIT_ADDRESS_PREFIX) return "testnet";
            return NaN;
        },
        addressToScript: function (a, A = {}) {
            defArgs(A, {hex: false});
            if (!tools.isString(a)) throw new Error('address invalid');
            let s;
            if ([C.TESTNET_SCRIPT_ADDRESS_PREFIX, C.MAINNET_SCRIPT_ADDRESS_PREFIX].includes(a[0])) {
                s = BC([B([O.OP_HASH160, 0x14]), this.addressToHash(a), B([O.OP_EQUAL])]);
                return (A.hex) ? s.toString('hex') : s;
            }
            if ([C.MAINNET_ADDRESS_PREFIX, C.TESTNET_ADDRESS_PREFIX, C.TESTNET_ADDRESS_PREFIX_2].includes(a[0])) {
                s = BC([B([O.OP_DUP, O.OP_HASH160, 0x14]), this.addressToHash(a), B([O.OP_EQUALVERIFY, O.OP_CHECKSIG])]);
                return (A.hex) ? s.toString('hex') : s;
            }
            if ([C.TESTNET_SEGWIT_ADDRESS_PREFIX, C.MAINNET_SEGWIT_ADDRESS_PREFIX].includes(a.split("1")[0])) {
                let h = this.addressToHash(a);
                s = BC([B([O.OP_0, h.length]), this.addressToHash(a)]);
                return (A.hex) ? s.toString('hex') : s;
            }
            throw new Error('address invalid');
        },
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
        publicKeyToP2SH_P2WPKHScript: (h, A = {}) => {
            defArgs(A, {hex: false});
            h = getBuffer(h);
            if (h.length !== 33) throw new Error("public key len invalid");
            let s = BC([B([0, 0x14]), hash.hash160(h)]);
            return (A.hex) ? s.toString('hex') : s;
        },
        getWitnessVersion: (address) => encoders.rebase_32_to_5(address.split(1)[1])[0],
        isAddressValid: (address, A = {}) => {
            defArgs(A, {testnet: false});
            if (!tools.isString(address)) return false;

            if ([C.MAINNET_ADDRESS_PREFIX,
                C.MAINNET_SCRIPT_ADDRESS_PREFIX,
                C.TESTNET_ADDRESS_PREFIX,
                C.TESTNET_ADDRESS_PREFIX_2,
                C.TESTNET_SCRIPT_ADDRESS_PREFIX].includes(address[0])) {
                if (A.testnet === true) {
                    if (!([C.TESTNET_ADDRESS_PREFIX,
                        C.TESTNET_ADDRESS_PREFIX_2,
                        C.TESTNET_SCRIPT_ADDRESS_PREFIX].includes(address[0]))) return false;
                }
                else if (![C.MAINNET_ADDRESS_PREFIX,
                    C.MAINNET_SCRIPT_ADDRESS_PREFIX].includes(address[0])) return false;
                let b = encoders.decodeBase58(address, {hex: false});
                if (b.length !== 25) return false;
                let checksum = b.slice(-4);
                let verifyChecksum = hash.doubleSha256(b.slice(0, -4)).slice(0, 4);
                if (!checksum.equals(verifyChecksum)) return false;
                return true;
            } else {
                let prefix, payload;
                if ([C.TESTNET_SEGWIT_ADDRESS_PREFIX,
                    C.MAINNET_SEGWIT_ADDRESS_PREFIX].includes(address.split("1")[0].toLowerCase())) {
                    if (address.length !== 42 && address.length !== 62) return false;
                    let pp = address.split('1');
                    prefix = pp[0];
                    payload = pp[1];
                    let upp;
                    if (prefix[0] === prefix[0].toLowerCase()) {
                        upp = false;
                    } else {
                        upp = true;
                    }
                    for (let i = 0; i < payload.length; i++)
                        if (upp === true) {
                            if (C.BASE32CHARSET_UPCASE.indexOf(payload[i]) === -1) return false;
                        } else {
                            if (C.BASE32CHARSET.indexOf(payload[i]) === -1) return false;
                        }
                    payload = payload.toLowerCase();
                    prefix = prefix.toLowerCase();
                    let stripped_prefix;
                    if (A.testnet === true) {
                        if (prefix !== C.TESTNET_SEGWIT_ADDRESS_PREFIX) return false;
                        stripped_prefix = C.TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                    } else {
                        if (prefix !== C.MAINNET_SEGWIT_ADDRESS_PREFIX) return false;
                        stripped_prefix = C.MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                    }
                    let d = encoders.rebase_32_to_5(payload);
                    let h = d.slice(0, -6);
                    let checksum = d.slice(-6);
                    stripped_prefix = stripped_prefix.concat(h).concat([0, 0, 0, 0, 0, 0]);
                    let checksum2 = encoders.bech32Polymod(stripped_prefix);
                    checksum2 = encoders.rebase_8_to_5(tools.intToBytes(checksum2, 5)).slice(2);
                    if (tools.bytesToString(checksum) !== tools.bytesToString(checksum2)) return false;
                    return true;
                }
                return false;
            }
        }
    }
};


