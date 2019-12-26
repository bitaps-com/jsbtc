
var int_base32_map = {};
var base32_int_map = {};

var base32charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
var base32charset_upcase = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";

for (let i = 0; i < base32charset.length; i++) {
    int_base32_map[base32charset[i]] = i;
    base32_int_map[i] = base32charset.charCodeAt(i);
}
for (let i = 0; i < base32charset_upcase.length; i++) {
    int_base32_map[base32charset_upcase[i]] = i;
}



module.exports = {
    base58Alphabet: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    base32charset: base32charset,
    base32charset_upcase: base32charset_upcase,
    int_base32_map: int_base32_map,
    base32_int_map: base32_int_map,
    MAINNET_ADDRESS_PREFIX: '1',
    TESTNET_ADDRESS_PREFIX: 'm',
    TESTNET_ADDRESS_PREFIX_2:'n',
    MAINNET_SCRIPT_ADDRESS_PREFIX: '3',
    TESTNET_SCRIPT_ADDRESS_PREFIX: '2',
    MAINNET_SEGWIT_ADDRESS_PREFIX: 'bc',
    TESTNET_SEGWIT_ADDRESS_PREFIX: 'tb',
    MAINNET_ADDRESS_BYTE_PREFIX: [0],
    TESTNET_ADDRESS_BYTE_PREFIX: [111],
    MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX: [5],
    TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX: [196],
    MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX: [3, 3, 0, 2, 3],
    TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX: [3, 3, 0, 20, 2]
};