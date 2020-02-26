const __btcCryptoJS = require('./btc_crypto.js');
const constants = require('./constants.js');
const tools = require('./functions/tools.js');
const opcodes = require('./opcodes.js');
const hash = require('./functions/hash.js');
const encoders = require('./functions/encoders.js');
const mnemonicWordlist = require('./bip39_wordlist.js');
const mnemonic = require('./functions/bip39_mnemonic.js');
const key = require('./functions/key.js');
const address = require('./functions/address.js');
const script = require('./functions/script.js');
const Address = require('./classes/address.js');
const Transation = require('./classes/transaction.js');

module.exports = {
    __initTask: null,
    asyncInit: async function (scope) {
        if (this.__initTask === null) {
            this.__initTask = await this.__asyncInit(scope);
        } else {
            if (this.__initTask !== "completed") {
                await this.__initTask;
            }
        }
    },
    __asyncInit: async function (scope) {
        if (scope === undefined) scope = this;
        constants(scope);
        tools(scope);
        opcodes(scope);
        scope.__bitcoin_core_crypto = await this.__initCryptoModule();
        hash(scope);
        encoders(scope);
        mnemonic(scope);
        mnemonicWordlist(scope);

        scope.secp256k1PrecompContextSign = scope.__bitcoin_core_crypto.module._secp256k1_context_create(scope.SECP256K1_CONTEXT_SIGN);
        scope.secp256k1PrecompContextVerify = scope.__bitcoin_core_crypto.module._secp256k1_context_create(scope.SECP256K1_CONTEXT_VERIFY);
        let seed = scope.generateEntropy({'hex': false});
        let seedPointer = scope.__bitcoin_core_crypto.module._malloc(seed.length);
        scope.__bitcoin_core_crypto.module.HEAPU8.set(seed, seedPointer);
        scope.__bitcoin_core_crypto.module._secp256k1_context_randomize(scope.secp256k1PrecompContextSign, seedPointer);

        key(scope);
        address(scope);
        script(scope);
        Address(scope);
        Transation(scope);

        this.__initTask = "completed";
    },
    __initCryptoModule: () => {
        return new Promise(function (resolve) {
            __btcCryptoJS().then((module) => {
                resolve({module});
            });
        });
    },
}






