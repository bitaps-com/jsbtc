module.exports = function (constants, hash, encoders, tools) {
    let Buffer = tools.Buffer;
    let isBuffer = tools.isBuffer;

    return {
        hashToAddress: function(ha, named_args = {testnet: false, script_hash: false, witness_version: 0}) {
            if (named_args.testnet === undefined) named_args.testnet = false;
            if (named_args.script_hash === undefined) named_args.script_hash = false;
            if (named_args.witness_version === undefined) named_args.witness_version = 0;
            if (!isBuffer(ha)) {
                if (tools.isString(ha)) {
                    ha = Buffer.from(ha, 'hex');
                } else throw new Error('address hash invalid, expected bytes Buffer or hex string');
            }
            let prefix;
            if (!named_args.script_hash) {

                if (isNaN(named_args.witness_version)) {

                    if (ha.length !== 20)  throw new Error('address hash length incorrect');
                    if (named_args.testnet)  prefix = Buffer.from(constants.TESTNET_ADDRESS_BYTE_PREFIX);
                    else prefix = Buffer.from(constants.MAINNET_ADDRESS_BYTE_PREFIX);
                    let h = Buffer.concat([prefix, ha]);
                    h = Buffer.concat([h, hash.doubleSha256(h,{hex:false}).slice(0,4)]);
                    return encoders.encodeBase58(h);
                } else {
                    if ((ha.length !== 20)&&(ha.length !== 32)) throw new Error('address hash length incorrect');
                }
            }

            if (isNaN(named_args.witness_version)) {
                if (named_args.testnet)  prefix = Buffer.from(constants.TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX);
                else prefix = Buffer.from(constants.MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX);
                let h = Buffer.concat([prefix, ha]);
                h = Buffer.concat([h, hash.doubleSha256(h,{hex:false}).slice(0,4)]);
                return encoders.encodeBase58(h);
            }

            let hrp;
            if (named_args.testnet) {
                prefix = constants.TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                hrp = constants.TESTNET_SEGWIT_ADDRESS_PREFIX;
            } else {
                prefix = constants.MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                hrp = constants.MAINNET_SEGWIT_ADDRESS_PREFIX;
            }
            ha =  encoders.rebase_8_to_5(Array.from(ha));
            ha.unshift(named_args.witness_version);

            let checksum = encoders.bech32Polymod(prefix.concat(ha.concat([0,0,0,0,0,0])));
            checksum = encoders.rebase_8_to_5(tools.intToBytes(checksum, 5)).slice(2);
            return hrp + '1' + encoders.rebase_5_to_32(ha.concat(checksum), false);;

        },
        addressToHash: function(a, named_args = {hex: false}) {
            if (named_args.hex === undefined) named_args.hex = false;

            if (!tools.isString(a)) throw new Error('address invalid');

            let h;
            if (constants.ADDRESS_PREFIX_LIST.includes(a[0])) {
                h = encoders.decodeBase58(a, {hex:false});
                h = h.slice(1, h.length - 4);
            } else if ([constants.MAINNET_SEGWIT_ADDRESS_PREFIX,
                        constants.TESTNET_SEGWIT_ADDRESS_PREFIX].includes(a.split('1')[0])) {
                let q = encoders.rebase_32_to_5(a.split('1')[1]);
                h = encoders.rebase_5_to_8(q.slice(1, q.length-6), false);
                h = Buffer.from(h);
            } else return NaN;
            return (named_args.hex)? h.toString('hex'): h;
        },

        publicKeyToAddress: function(pubkey, named_args = {testnet: false, p2sh_p2wpkh: false, witness_version: 0}){
            if (named_args.testnet === undefined) named_args.testnet = false;
            if (named_args.p2sh_p2wpkh === undefined) named_args.p2sh_p2wpkh = false;
            if (named_args.witness_version === undefined) named_args.witness_version = 0;

            if (!isBuffer(pubkey)) {
                if (tools.isString(pubkey)) {
                    pubkey = Buffer.from(pubkey, 'hex');
                } else throw new Error('public key invalid, expected bytes Buffer or hex string');
            }
            let h;
            if (named_args.p2sh_p2wpkh) {
                if (pubkey.length !== 33) throw new Error('public key invalid, expected bytes Buffer or hex string');
                h = hash.hash160(Buffer.concat([Buffer.from([0,20]), hash.hash160(pubkey)]));
                named_args.witness_version = NaN
            }
            else {
                if (!isNaN(named_args.witness_version))
                    if (pubkey.length !== 33) throw new Error('public key invalid');
                h = hash.hash160(pubkey);
            }
            named_args.script_hash = named_args.p2sh_p2wpkh;
            return this.hashToAddress(h, named_args);


        },

        is_address_valid: function (address, testnet) {
            if (testnet === undefined) testnet = false;
            if (typeof(address) !== "string") return false;
            if ([constants.MAINNET_ADDRESS_PREFIX,
                constants.MAINNET_SCRIPT_ADDRESS_PREFIX,
                constants.TESTNET_ADDRESS_PREFIX,
                constants.TESTNET_ADDRESS_PREFIX_2,
                constants.TESTNET_SCRIPT_ADDRESS_PREFIX].includes(address[0])) {
                if (testnet === true)
                    if (!([constants.TESTNET_ADDRESS_PREFIX,
                        constants.TESTNET_ADDRESS_PREFIX_2,
                        constants.TESTNET_SCRIPT_ADDRESS_PREFIX].includes(address[0])))
                        return false;
                    else if (!(address[0] in [constants.MAINNET_ADDRESS_PREFIX,
                        constants.MAINNET_SCRIPT_ADDRESS_PREFIX]))
                        return false;
                let b = encoders.base58decode(address);
                if (b.length !== 25) return false;
                let checksum = b.slice(-4);
                let verify_checksum = hash.double_sha256(b.slice(0, b.length - 4), {hex: true}).slice(0, 4);
                if (checksum.toString() !== verify_checksum.toString()) return false;
                return true;
            }
            else {
                let prefix, payload;
                if ([constants.TESTNET_SEGWIT_ADDRESS_PREFIX,
                    constants.MAINNET_SEGWIT_ADDRESS_PREFIX].includes(address.slice(0, 2).toLowerCase())) {
                    if (address.length !== 42 && address.length !== 62) return false;

                    try {
                        let pp = address.split('1');
                        prefix = pp[0];
                        payload = pp[1];
                    }
                    catch (e) {
                        return false;
                    }
                    let upp;
                    if (prefix[0] === prefix[0].toLowerCase()) {
                        upp = false;
                    }
                    else {
                        upp = true;
                    }
                    for (let i = 0; i < payload.length; i++)
                        if (upp === true) {
                            if (constants.base32charset_upcase.indexOf(payload[i]) === -1) return false;
                        }
                        else {
                            if (constants.base32charset.indexOf(payload[i]) === -1) return false;
                        }
                    payload = payload.toLowerCase();
                    prefix = prefix.toLowerCase();
                    if (testnet === true) {

                        if (prefix !== constants.TESTNET_SEGWIT_ADDRESS_PREFIX) return false;
                        stripped_prefix = constants.TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                    }
                    else {
                        if (prefix !== constants.MAINNET_SEGWIT_ADDRESS_PREFIX) return false;
                        stripped_prefix = constants.MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX;
                    }
                    d = encoders.rebase_32_to_5(payload);
                    address_hash = d.slice(0, -6);
                    checksum = d.slice(-6);
                    stripped_prefix.push.apply(stripped_prefix, address_hash);
                    stripped_prefix.push.apply(stripped_prefix, [0, 0, 0, 0, 0, 0]);

                    checksum2 = encoders.bech32_polymod(stripped_prefix);
                    checksum2 = encoders.rebase_8_to_5(intToBytes(checksum2, 5)).slice(2);
                    if (bytesToString(checksum) !== bytesToString(checksum2)) return false;
                    return true;
                }
                return false;
            }
        }
    }
};


