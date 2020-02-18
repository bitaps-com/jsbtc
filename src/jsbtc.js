const __btcCryptoJS = require('./btc_crypto.js');
const constants = require('./constants.js');
const tools = require('./functions/tools.js');
const opcodes = require('./opcodes.js');
const hashInit = require('./functions/hash.js');
const encodersInit = require('./functions/encoders.js');
const mnemonicInit = require('./functions/bip39_mnemonic.js');
const keyInit = require('./functions/key.js');
const addressInit = require('./functions/address.js');
const scriptInit = require('./functions/script.js');

module.exports = {
    __initTask: null,
    asyncInit : async function () {
        if  (this.__initTask === null) {
        this.__initTask = await this.__asyncInit();
        } else {
            if  (this.__initTask!=="completed") {
                await this.__initTask;
            }
        }
    },
    __asyncInit : async function () {

        let _crypto = await this.__initCryptoModule();

    let hash = hashInit(_crypto, tools);
    this.sha256 = hash.sha256;
    this.doubleSha256 = hash.doubleSha256;
    this.siphash = hash.siphash;
    this.ripemd160 = hash.ripemd160;
    this.hash160 = hash.hash160;

    let encoders = encodersInit(constants, _crypto, tools);
    this.encodeBase58 = encoders.encodeBase58;
    this.decodeBase58 = encoders.decodeBase58;

    let mnemonic = mnemonicInit(constants, tools);
    this.generate_entropy = mnemonic.generateEntropy;
    this.igam = mnemonic.igam;
    this.igamc = mnemonic.igamc;

    this.secp256k1PrecompContextSign = _crypto.module._secp256k1_context_create(constants.SECP256K1_CONTEXT_SIGN);
    this.secp256k1PrecompContextVerify = _crypto.module._secp256k1_context_create(constants.SECP256K1_CONTEXT_VERIFY);
    let seed = mnemonic.generateEntropy({'hex': false});
    let seedPointer = _crypto.module._malloc(seed.length);
    _crypto.module.HEAPU8.set(seed, seedPointer);
    _crypto.module._secp256k1_context_randomize(this.secp256k1PrecompContextSign, seedPointer);


    let key = keyInit(constants, _crypto, tools, mnemonic, encoders, hash,
        this.secp256k1PrecompContextSign, this.secp256k1PrecompContextVerify);
    this.createPrivateKey = key.createPrivateKey;
    this.privateKeyToWif = key.privateKeyToWif;
    this.wifToPrivateKey = key.wifToPrivateKey;
    this.isWifValid = key.isWifValid;
    this.privateToPublicKey = key.privateToPublicKey;
    this.isPublicKeyValid = key.isPublicKeyValid;

    let address = addressInit(constants, hash, encoders, tools, opcodes);
    this.hashToAddress = address.hashToAddress;
    this.addressToHash = address.addressToHash;
    this.publicKeyToAddress = address.publicKeyToAddress;
    this.addressType = address.addressType;
    this.addressNetType = address.addressNetType;
    this.addressToScript = address.addressToScript;
    this.hashToScript = address.hashToScript;
    this.publicKeyToP2SH_P2WPKHScript = address.publicKeyToP2SH_P2WPKHScript;
    this.getWitnessVersion = address.getWitnessVersion;
    this.isAddressValid = address.isAddressValid;

    let script = scriptInit(constants, hash, encoders, tools, opcodes,
                            address, key, _crypto, this.secp256k1PrecompContextSign,
                            this.secp256k1PrecompContextVerify);
    this.hashToScript = script.hashToScript;
    this.publicKeyToP2SH_P2WPKHScript = script.publicKeyTo_P2SH_P2WPKH_Script;
    this.publicKeyTo_PUBKEY_Script = script.publicKeyTo_PUBKEY_Script;
    this.parseScript = script.parseScript;
    this.scriptToAddress = script.scriptToAddress;
    this.decodeScript = script.decodeScript;
    this.delete_from_script = script.delete_from_script;
    this.scriptToHash = script.scriptToHash;
    this.opPushData = script.opPushData;
    this.readOpcode = script.readOpcode;
    this.signMessage = script.signMessage;
    this.verifySignature = script.verifySignature;
    this.publicKeyRecovery = script.publicKeyRecovery;


    this.opcodes = opcodes;
    this.tools = tools;
    this.constants = constants;
    this.Buffer = tools.Buffer;
    this.isBuffer = tools.isBuffer;

        this.__initTask = "completed";
    },
    __initCryptoModule : () => {
        return new Promise(function(resolve) {
            __btcCryptoJS().then((module) => {
                resolve({module});
            });
        });
    },
}






