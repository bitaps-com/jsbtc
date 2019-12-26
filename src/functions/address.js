var constants = require('../constants.js');


function is_address_valid(address, testnet) {
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
        let b = base58decode(address);
        if (b.length !== 25) return false;
        let checksum = b.slice(-4);
        let verify_checksum = double_sha256(b.slice(0, b.length - 4), {asBytes: true}).slice(0, 4);
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
            d = rebase_32_to_5(payload);
            address_hash = d.slice(0, -6);
            checksum = d.slice(-6);
            stripped_prefix.push.apply(stripped_prefix, address_hash);
            stripped_prefix.push.apply(stripped_prefix, [0, 0, 0, 0, 0, 0]);

            checksum2 = bech32_polymod(stripped_prefix);
            checksum2 = rebase_8_to_5(intToBytes(checksum2, 5)).slice(2);
            if (bytesToString(checksum) !== bytesToString(checksum2)) return false;
            return true;
        }
        return false;
    }
}


module.exports = {
    is_address_valid
};