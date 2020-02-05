'use strict';
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');


function crypto_test() {
console.log("crytpo test");
var key = ec.genKeyPair();
console.log(key.priv);

console.log(key.priv);
}

module.exports = {
    crypto_test
};