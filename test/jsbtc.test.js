const jsbtc = require('../jsbtc.js');
const chai = require('chai');
chai.use(require("chai-as-promised"));
const expect = chai.expect;
const assert = require('chai').assert;

describe("Test jsbtc library", function() {
    it('Asynchronous initialization', async () => {
        await jsbtc.asyncInit();
    });
    describe("Hash functions:", function(){
        it('sha256',  () => {
            assert.equal(jsbtc.sha256("test sha256", {hex: true}),
                         "c71d137da140c5afefd7db8e7a255df45c2ac46064e934416dc04020a91f3fd2");
            assert.equal(jsbtc.sha256("7465737420736861323536", {hex: true}),
                "c71d137da140c5afefd7db8e7a255df45c2ac46064e934416dc04020a91f3fd2");
            assert.equal(jsbtc.sha256("00bb", {hex:true, msgNotHex: true}),
                "bb88b952880c3a64d575449f8c767a53c52ce8f55f9c80f83e851aa6fce5bbea");
            assert.equal(jsbtc.sha256("30306262", {hex:true}),
                "bb88b952880c3a64d575449f8c767a53c52ce8f55f9c80f83e851aa6fce5bbea");
        })
        it('double sha256',  () => {
            assert.equal(jsbtc.doubleSha256("test double sha256", {hex: true}),
                "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");
            assert.equal(jsbtc.doubleSha256("7465737420646f75626c6520736861323536", {hex: true}),
                "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");
            assert.equal(jsbtc.doubleSha256("00bb", {hex:true, msgNotHex: true}),
                "824d078ceda8e8eb07cc8181a81f43c8855586c913dd7f54c94f05134e085d5f");
            assert.equal(jsbtc.doubleSha256("30306262", {hex:true}),
                "824d078ceda8e8eb07cc8181a81f43c8855586c913dd7f54c94f05134e085d5f");
        })

    });



    // before(function(done) {
    //     jsbtc.asyncInit().then(done).catch(done);
    // });
    // describe("Hash functions:", function(){
    //     it("sha256", function(){
    //         console.log(jsbtc);
    //         // let sha256 =
    //         // assert.equal(mnemonic.igam(0.56133437, 7.79533309) - 0.99989958147838275959 < q, true);
    //     });
    // });
});

//
// };





    // let s = k.hash.sha256("baz", {hex: 1, msgNotHex: 1});
    // console.log(s);
    // let y = Buffer.from()
    // console.log("x:->", x.toString('hex'));
    // let r = Buffer.from("822f51f5dd7f7f269bc9344b0eb6d9f290dad8eb8bcf7f89e92a78f1918d10e1", 'hex');
    // let bf = k.btc_crypto.module._malloc(r.length);
    // k.btc_crypto.module.HEAPU8.set(r, bf)
    // let spubkey = k.btc_crypto.module._malloc(32);
    // k.btc_crypto.module._crypto_sha256(bf,r.length, spubkey );
    //
    // let out = new Buffer(32)
    // for (let i=0; i<32; i++) {
    //     let v = k.btc_crypto.module.getValue(spubkey + i, 'i8')
    //     out[i] = v
    // }
    // console.log(">>>>>", out.toString('hex'));
    // console.log(">>>>>", r, r.length);
    // k.btc_crypto.module._free(bf);
    // k.btc_crypto.module._free(spubkey);

    // console.log(k);
    // k.btc_crypto._sayHi();
// };
// f();


// import Module from '../btc_crypto.js';
//
// let ModuleInstance;
//
// console.log(Module);
//
//
// const locateFile = '../btc_crypto.wasm'
// ? (path, prefix) => {
//     if (path.endsWith('.wasm')) {
//       return fileLocation
//     }
//
//     // keep default behaviour for non wasm files
//     return prefix + path
//   }
// : "./";
//
// console.log(locateFile,  ">>");
//
//
// function internalInitialise(moduleObject) {
//   return new Promise(resolve => {
//     console.log(__dirname);
//     Module(moduleObject).then(Module => {
//         console.log(__dirname);
//       // prevent an infinite loop: https://github.com/emscripten-core/emscripten/issues/5820
//       delete Module.then;
//       resolve(Module)
//     })
//   })
// }
// var __dirname ="./";
// console.log(__dirname);
// const dcgpModule =  internalInitialise({ locateFile:"", __dirname : "" });
// console.log(dcgpModule,  ">>");

// let k = res();
// console.log(res);
// const buffer = await res.arrayBuffer();
// const module = await WebAssembly.compile(buffer);

// let k = BTC_CRYPTO();

// em_module['onRuntimeInitialized'] = async function() {
//
//     return em_module;
// };

//
// console.log(em_module);
// let k = em_module();
// console.log(k);

// const instance = wasmModule({
//   onRuntimeInitialized() {
//     instance.sayHello();
//   }
// });
//
//
// const instance = BTC_CRYPTO({
//   onRuntimeInitialized() {
//     instance.sayHello();
//   }
// });


// p = new BTC_CRYPTO();
//
//
//   let options = {
//     instantiateWasm: function (info, successCallback) {
//       return btc_crypto_wasm(info).then(function (i) {
//                 return successCallback(i.instance)
//               })
//     }
//   };
//
//
//
// const i = _btc_crypto();
//
// console.log(i);


// describe('Address functions tests', function() {
//    it('test test', function() {
//        assert.equal('bar', 'bar');
//    });
//
//
// });

// describe('Hash functions tests', function() {
//        it('sha256', function() {
//        assert.equal(hash.sha256("7465737420646f75626c6520736861323536", {hex:true}),
//                     "c58fde6cd21f2c6849705b928181e180991f02e3a9427f748cdb9ed7b9d0a284");});
//        it('double_sha256', function() {
//        assert.equal(hash.double_sha256("7465737420646f75626c6520736861323536", {hex:true}),
//                     "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");});
//
// });

// describe('Crypto functions tests', function() {
// let p = 8798798;
//   // crypto._MapIntoRange(p, 8978998);
// });


// describe('bip39_mnemonic functions tests', function() {
//    it('igam and igamc math functions', function() {
//        let q = 0.0000000000001;
//        assert.equal(mnemonic.igam(0.56133437, 7.79533309) - 0.99989958147838275959 < q, true);
//        assert.equal(mnemonic.igam(3.80398274, 0.77658461) - 0.01162079725209424867 < q, true);
//        assert.equal(mnemonic.igam(6.71146614, 0.39790492) - 0.00000051486912406477 < q, true);
//        assert.equal(mnemonic.igam(5.05505886, 6.08602125) - 0.71809645160316382118 < q, true);
//        assert.equal(mnemonic.igam(9.45603411, 4.60043366) - 0.03112942473115925396 < q, true);
//        assert.equal(mnemonic.igamc(3.08284045, 0.79469709) - 0.95896191705843125686 < q, true);
//        assert.equal(mnemonic.igamc(7.91061495, 9.30889249) - 0.27834295370900602462 < q, true);
//        assert.equal(mnemonic.igamc(4.89616780, 5.75314859) - 0.30291667399717547848 < q, true);
//        assert.equal(mnemonic.igamc(8.11261940, 4.05857957) - 0.95010562492501993148 < q, true);
//        assert.equal(mnemonic.igamc(1.34835811, 6.64708856) - 0.00295250273836756942 < q, true);
//    });
//    let k = mnemonic.generate_entropy();
//    console.log(k);
//
//
// });
//
//

// export { BTC_CRYPTO };
