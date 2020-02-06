var assert = require('chai').assert;
var mnemonic = require('../functions/bip39_mnemonic');
var crypto = require('../crypto');
var hash = require('../functions/hash');

describe('Address functions tests', function() {
   it('test test', function() {
       assert.equal('bar', 'bar');
   });


});

describe('Hash functions tests', function() {
       it('sha256', function() {
       assert.equal(hash.sha256("7465737420646f75626c6520736861323536", {hex:true}),
                    "c58fde6cd21f2c6849705b928181e180991f02e3a9427f748cdb9ed7b9d0a284");});
       it('double_sha256', function() {
       assert.equal(hash.double_sha256("7465737420646f75626c6520736861323536", {hex:true}),
                    "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");});

});

describe('Crypto functions tests', function() {

  crypto.crypto_test();
});


describe('bip39_mnemonic functions tests', function() {
   it('igam and igamc math functions', function() {
       let q = 0.0000000000001;
       assert.equal(mnemonic.igam(0.56133437, 7.79533309) - 0.99989958147838275959 < q, true);
       assert.equal(mnemonic.igam(3.80398274, 0.77658461) - 0.01162079725209424867 < q, true);
       assert.equal(mnemonic.igam(6.71146614, 0.39790492) - 0.00000051486912406477 < q, true);
       assert.equal(mnemonic.igam(5.05505886, 6.08602125) - 0.71809645160316382118 < q, true);
       assert.equal(mnemonic.igam(9.45603411, 4.60043366) - 0.03112942473115925396 < q, true);
       assert.equal(mnemonic.igamc(3.08284045, 0.79469709) - 0.95896191705843125686 < q, true);
       assert.equal(mnemonic.igamc(7.91061495, 9.30889249) - 0.27834295370900602462 < q, true);
       assert.equal(mnemonic.igamc(4.89616780, 5.75314859) - 0.30291667399717547848 < q, true);
       assert.equal(mnemonic.igamc(8.11261940, 4.05857957) - 0.95010562492501993148 < q, true);
       assert.equal(mnemonic.igamc(1.34835811, 6.64708856) - 0.00295250273836756942 < q, true);
   });
   let k = mnemonic.generate_entropy();
   console.log(k);


});

//
// describe('test tests', function() {
//    it('t>>>', function() {
//        mnemonic.test();
//    });

//
// });


