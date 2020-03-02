# jsbtc

[![travis build](https://img.shields.io/travis/bitaps-com/jsbtc?style=plastic)](https://travis-ci.org/bitaps-com/jsbtc)
[![codecov coverage](https://img.shields.io/codecov/c/github/bitaps-com/jsbtc/beta?style=plastic)](https://codecov.io/gh/bitaps-com/jsbtc)
[![version](https://img.shields.io/npm/v/jsbtc.js/latest?style=plastic)](https://www.npmjs.com/package/jsbtc.js/v/latest)


JavaScript Bitcoin library


Under development

### Build:
    npm install jsbtc.js
    npm run build:wasm:prebuild
    npm run build:wasm
    npm run build
    npm run build:web
 
### Use in browser:
    <script src="jsbtc.test.js"></script>
    <script> ...
    // inside async function 
    var jsbtc = await jsbtc.asyncInit();
    ... </script>
