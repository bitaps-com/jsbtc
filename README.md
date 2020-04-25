<img src="docs/img/jsbtc.png" width="100">

## JavaScript Bitcoin library

[![travis build](https://img.shields.io/travis/bitaps-com/jsbtc?style=plastic)](https://travis-ci.org/bitaps-com/jsbtc)
[![codecov coverage](https://img.shields.io/codecov/c/github/bitaps-com/jsbtc/beta?style=plastic)](https://codecov.io/gh/bitaps-com/jsbtc)
[![version](https://img.shields.io/npm/v/jsbtc.js/latest?style=plastic)](https://www.npmjs.com/package/jsbtc.js/v/latest)


Crypto secp256k1 + wasm. Implemented: bip32, bip39, bip44, bip49, bip84, bip141. NIST random generation tests on the fly for entropy. Shamir's secret sharing for mnemonic.

### Build:
    npm install jsbtc.js
    npm run build:wasm:prebuild
    npm run build:wasm
    npm run build
    npm run build:web
 
### Use in browser:
    <script src="jsbtc.web.min.js"></script>
    <script> ...
    // inside async function 
    var jsbtc = await jsbtc.asyncInit();
    ... </script>
    
### Examples
    https://github.com/bitaps-com/jsbtc/blob/master/test/jsbtc.test.js
