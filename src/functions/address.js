module.exports = function (S) {
    let Buffer = S.Buffer;
    let ARGS = S.defArgs;
    let getBuffer = S.getBuffer;
    let BF = Buffer.from;
    let BC = Buffer.concat;
    let O = S.OPCODE;

    S.hashToAddress = (ha, A = {}) => {
        ARGS(A, {testnet: false, scriptHash: false, witnessVersion: 0});
        ha = getBuffer(ha);
        let prefix;
        if (!A.scriptHash) {
            if (A.witnessVersion === null) {
                if (ha.length !== 20) throw new Error('address hash length incorrect');
                if (A.testnet) prefix = BF(S.TESTNET_ADDRESS_BYTE_PREFIX);
                else prefix = BF(S.MAINNET_ADDRESS_BYTE_PREFIX);
                let h = BC([prefix, ha]);
                h = BC([h, S.doubleSha256(h, {hex: false}).slice(0, 4)]);
                return S.encodeBase58(h);
            } else if ((ha.length !== 20) && (ha.length !== 32))
                throw new Error('address hash length incorrect');
        }

        if (A.witnessVersion === null) {
            if (A.testnet) prefix = BF(S.TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX);
            else prefix = BF(S.MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX);
            let h = BC([prefix, ha]);
            h = BC([h, S.doubleSha256(h, {hex: false}).slice(0, 4)]);
            return S.encodeBase58(h);
        }

        let hrp;
        if (A.testnet) {
            prefix = S.TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX;
            hrp = S.TESTNET_SEGWIT_ADDRESS_PREFIX;
        } else {
            prefix = S.MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX;
            hrp = S.MAINNET_SEGWIT_ADDRESS_PREFIX;
        }
        ha = S.rebase_8_to_5(Array.from(ha));
        ha.unshift(A.witnessVersion);

        let checksum = S.bech32Polymod(prefix.concat(ha.concat([0, 0, 0, 0, 0, 0])));
        checksum = S.rebase_8_to_5(S.intToBytes(checksum, 5, 'big')).slice(2);
        return hrp + '1' + S.rebase_5_to_32(ha.concat(checksum), false);
    };

    S.addressToHash = (a, A = {}) => {
        ARGS(A, {hex: false});
        if (!S.isString(a)) throw new Error('address invalid');
        let h;
        if (S.ADDRESS_PREFIX_LIST.includes(a[0])) {
            h = S.decodeBase58(a, {hex: false});
            h = h.slice(1, h.length - 4);
        } else if ([S.MAINNET_SEGWIT_ADDRESS_PREFIX,
            S.TESTNET_SEGWIT_ADDRESS_PREFIX].includes(a.split('1')[0])) {
            let q = S.rebase_32_to_5(a.split('1')[1]);
            h = BF(S.rebase_5_to_8(q.slice(1, q.length - 6), false));
        } else return null;
        return (A.hex) ? h.hex() : h;
    };

    S.publicKeyToAddress = (pubkey, A = {}) => {
        ARGS(A, {testnet: false, p2sh_p2wpkh: false, witnessVersion: 0});
        pubkey = getBuffer(pubkey);
        let h;
        if (A.p2sh_p2wpkh) {
            if (pubkey.length !== 33) throw new Error('public key length invalid');
            h = S.hash160(BC([BF([0, 20]), S.hash160(pubkey)]));
            A.witnessVersion = null
        } else {
            if (A.witnessVersion !== null)
                if (pubkey.length !== 33) throw new Error('public key length invalid');
            h = S.hash160(pubkey);
        }
        A.scriptHash = A.p2sh_p2wpkh;
        return S.hashToAddress(h, A);
    };

    S.addressType = (a, A = {}) => {
        ARGS(A, {num: false});
        if ([S.TESTNET_SCRIPT_ADDRESS_PREFIX, S.MAINNET_SCRIPT_ADDRESS_PREFIX].includes(a[0]))
            return (A.num) ? S.SCRIPT_TYPES["P2SH"] : "P2SH";
        if ([S.MAINNET_ADDRESS_PREFIX, S.TESTNET_ADDRESS_PREFIX, S.TESTNET_ADDRESS_PREFIX_2].includes(a[0]))
            return (A.num) ? S.SCRIPT_TYPES["P2PKH"] : "P2PKH";
        if ([S.MAINNET_SEGWIT_ADDRESS_PREFIX, S.TESTNET_SEGWIT_ADDRESS_PREFIX].includes(a.slice(0, 2))) {
            if (a.length === 42) return (A.num) ? S.SCRIPT_TYPES["P2WPKH"] : "P2WPKH";
            if (a.length === 62) return (A.num) ? S.SCRIPT_TYPES["P2WSH"] : "P2WSH";
        }
        return (A.num) ? S.SCRIPT_TYPES["NON_STANDARD"] : "NON_STANDARD";
    };

    S.addressNetType = (a) => {
        if ([S.MAINNET_SCRIPT_ADDRESS_PREFIX, S.MAINNET_ADDRESS_PREFIX].includes(a[0])) return "mainnet";
        if (a.slice(0, 2) === S.MAINNET_SEGWIT_ADDRESS_PREFIX) return "mainnet";
        if ([S.TESTNET_SCRIPT_ADDRESS_PREFIX,
            S.TESTNET_ADDRESS_PREFIX, S.TESTNET_ADDRESS_PREFIX_2].includes(a[0])) return "testnet";
        if (a.slice(0, 2) === S.TESTNET_SEGWIT_ADDRESS_PREFIX) return "testnet";
        return null;
    };

    S.addressToScript = (a, A = {}) => {
        ARGS(A, {hex: false});
        if (!S.isString(a)) throw new Error('address invalid');
        let s;
        if ([S.TESTNET_SCRIPT_ADDRESS_PREFIX, S.MAINNET_SCRIPT_ADDRESS_PREFIX].includes(a[0])) {
            s = BC([BF([O.OP_HASH160, 0x14]), S.addressToHash(a), BF([O.OP_EQUAL])]);
            return (A.hex) ? s.hex() : s;
        }
        if ([S.MAINNET_ADDRESS_PREFIX, S.TESTNET_ADDRESS_PREFIX, S.TESTNET_ADDRESS_PREFIX_2].includes(a[0])) {
            s = BC([BF([O.OP_DUP, O.OP_HASH160, 0x14]), S.addressToHash(a), BF([O.OP_EQUALVERIFY, O.OP_CHECKSIG])]);
            return (A.hex) ? s.hex() : s;
        }
        if ([S.TESTNET_SEGWIT_ADDRESS_PREFIX, S.MAINNET_SEGWIT_ADDRESS_PREFIX].includes(a.split("1")[0])) {
            let h = S.addressToHash(a);
            s = BC([BF([O.OP_0, h.length]), S.addressToHash(a)]);
            return (A.hex) ? s.hex() : s;
        }
        throw new Error('address invalid');
    };

    S.getWitnessVersion = (address) => S.rebase_32_to_5(address.split(1)[1])[0];

    S.isAddressValid = (address, A = {}) => {
        ARGS(A, {testnet: false});
        if (!S.isString(address)) return false;

        if ([S.MAINNET_ADDRESS_PREFIX,
            S.MAINNET_SCRIPT_ADDRESS_PREFIX,
            S.TESTNET_ADDRESS_PREFIX,
            S.TESTNET_ADDRESS_PREFIX_2,
            S.TESTNET_SCRIPT_ADDRESS_PREFIX].includes(address[0])) {
            if (A.testnet === true) {
                if (!([S.TESTNET_ADDRESS_PREFIX,
                    S.TESTNET_ADDRESS_PREFIX_2,
                    S.TESTNET_SCRIPT_ADDRESS_PREFIX].includes(address[0]))) return false;
            } else if (![S.MAINNET_ADDRESS_PREFIX,
                S.MAINNET_SCRIPT_ADDRESS_PREFIX].includes(address[0])) return false;
            let b = S.decodeBase58(address, {hex: false});
            if (b.length !== 25) return false;
            let checksum = b.slice(-4);
            let verifyChecksum = S.doubleSha256(b.slice(0, -4)).slice(0, 4);
            return checksum.equals(verifyChecksum);

        } else {
            let prefix, payload;
            if ([S.TESTNET_SEGWIT_ADDRESS_PREFIX,
                S.MAINNET_SEGWIT_ADDRESS_PREFIX].includes(address.split("1")[0].toLowerCase())) {
                if (address.length !== 42 && address.length !== 62) return false;
                let pp = address.split('1');
                prefix = pp[0];
                payload = pp[1];
                let upp;
                upp = prefix[0] !== prefix[0].toLowerCase();
                for (let i = 0; i < payload.length; i++)
                    if (upp === true) {
                        if (S.BASE32CHARSET_UPCASE.indexOf(payload[i]) === -1) return false;
                    } else {
                        if (S.BASE32CHARSET.indexOf(payload[i]) === -1) return false;
                    }
                payload = payload.toLowerCase();
                prefix = prefix.toLowerCase();
                let strippedPrefix;
                if (A.testnet === true) {
                    if (prefix !== S.TESTNET_SEGWIT_ADDRESS_PREFIX) return false;
                    strippedPrefix = S.TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                } else {
                    if (prefix !== S.MAINNET_SEGWIT_ADDRESS_PREFIX) return false;
                    strippedPrefix = S.MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                }
                let d = S.rebase_32_to_5(payload);
                let h = d.slice(0, -6);
                let checksum = d.slice(-6);
                strippedPrefix = strippedPrefix.concat(h).concat([0, 0, 0, 0, 0, 0]);
                let checksum2 = S.bech32Polymod(strippedPrefix);
                checksum2 = S.rebase_8_to_5(S.intToBytes(checksum2, 5, 'big')).slice(2);
                return S.bytesToString(checksum) === S.bytesToString(checksum2);
            }
            return false;
        }
    };
};


