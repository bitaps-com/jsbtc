var browser = true;
try {
    var jsbtc = require('../src/jsbtc.js');
    var chai = require('chai');
    chai.use(require("chai-as-promised"));
    browser = false;
} catch (e) {
    console.log(e);
}


const assert = chai.assert;
const expect = chai.expect;

describe(`${(browser)? 'Browser':'Node'} test jsbtc library`, function() {
    it('Asynchronous initialization', async () => {
        await jsbtc.asyncInit();
    });
    describe("Hash functions:", function(){
        it('sha256',  () => {
            assert.equal(jsbtc.sha256("test sha256", {hex: true}),
                         "c71d137da140c5afefd7db8e7a255df45c2ac46064e934416dc04020a91f3fd2");
            assert.equal(jsbtc.sha256("7465737420736861323536", {hex: true}),
                "c71d137da140c5afefd7db8e7a255df45c2ac46064e934416dc04020a91f3fd2");
            assert.equal(jsbtc.sha256("00bb", {hex:true, encoding: 'utf8'}),
                "bb88b952880c3a64d575449f8c767a53c52ce8f55f9c80f83e851aa6fce5bbea");
            assert.equal(jsbtc.sha256("30306262", {hex:true}),
                "bb88b952880c3a64d575449f8c767a53c52ce8f55f9c80f83e851aa6fce5bbea");
            assert.equal(jsbtc.sha256(jsbtc.tools.stringToBytes("test sha256"), {hex: true}),
                "c71d137da140c5afefd7db8e7a255df45c2ac46064e934416dc04020a91f3fd2");
        });
        it('double sha256',  () => {
            assert.equal(jsbtc.doubleSha256("test double sha256", {hex: true}),
                "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");
            assert.equal(jsbtc.doubleSha256(jsbtc.tools.stringToBytes("test double sha256"), {hex: true}),
                "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");
            assert.equal(jsbtc.doubleSha256("7465737420646f75626c6520736861323536", {hex: true}),
                "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d");
            assert.equal(jsbtc.doubleSha256("00bb", {encoding: "utf8", hex:true}),
                "824d078ceda8e8eb07cc8181a81f43c8855586c913dd7f54c94f05134e085d5f");
            assert.equal(jsbtc.doubleSha256("30306262", {hex:true}),
                "824d078ceda8e8eb07cc8181a81f43c8855586c913dd7f54c94f05134e085d5f");
        });
        it('siphash',  () => {
            let v0 = new jsbtc.tools.BN ("0706050403020100", 16);
            let v1 = new jsbtc.tools.BN ("0F0E0D0C0B0A0908", 16);
            assert.equal(jsbtc.siphash("000102030405060708090a0b0c0d0e0f",
                                       {v0: v0, v1: v1}).toString('hex'),
                                      "3f2acc7f57c29bdb");
            assert.equal(jsbtc.siphash("0001020304050607",
                                       {v0: v0, v1: v1}).toString('hex'),
                                       "93f5f5799a932462");

            assert.equal(jsbtc.siphash("",{v0: v0, v1: v1}).toString('hex'),
                         "726fdb47dd0e0e31");
            assert.equal(jsbtc.siphash("siphash test").toString('hex'),
                "84c247dc01541d54");
            assert.equal(jsbtc.siphash(jsbtc.tools.stringToBytes("siphash test")).toString('hex'),
                "84c247dc01541d54");
            expect(() => jsbtc.siphash("",{v0: 43, v1: v1}).toString('hex')).to.throw('siphash init vectors v0, v1 must be BN instance');
            expect(() => jsbtc.siphash("",{v0: v0, v1: 11}).toString('hex')).to.throw('siphash init vectors v0, v1 must be BN instance');

        });

        it('ripemd160',  () => {
            assert.equal(jsbtc.ripemd160("test hash160", {hex: true}),
                "46a80bd289028559818a222eea64552d7a6a966f");
            assert.equal(jsbtc.ripemd160(jsbtc.tools.stringToBytes("test hash160"), {hex: true}),
                "46a80bd289028559818a222eea64552d7a6a966f");
            assert.equal(jsbtc.ripemd160("746573742068617368313630", {hex: true}),
                "46a80bd289028559818a222eea64552d7a6a966f");
            assert.equal(jsbtc.Buffer.from("46a80bd289028559818a222eea64552d7a6a966f", 'hex').equals(jsbtc.ripemd160("746573742068617368313630")),
                true);
            assert.equal(jsbtc.Buffer.from("46a80bd289028559818a222eea64552d7a6a966f", 'hex').equals(jsbtc.ripemd160("146573742068617368313630")),
                false);
        });

        it('hash160',  () => {
            assert.equal(jsbtc.hash160("test hash160", {hex: true}),
                "b720061a734285a70e86cb32b31f32884e198c32");
            assert.equal(jsbtc.hash160("746573742068617368313630", {hex: true}),
                "b720061a734285a70e86cb32b31f32884e198c32");
            assert.equal(jsbtc.Buffer.from("b720061a734285a70e86cb32b31f32884e198c32", 'hex').equals(jsbtc.hash160("746573742068617368313630")),
                true);
            assert.equal(jsbtc.Buffer.from("b720061a734285a70e86cb32b31f32884e198c32", 'hex').equals(jsbtc.hash160("146573742068617368313630")),
                false);
        });


    });

    describe("Encoder functions:", function(){
        it('encodeBase58',  () => {
            assert.equal(jsbtc.encodeBase58("000002030405060708090a0b0c0d0e0f"),
                "11ju1bKJX8HGdT7YmKLi");
            assert.equal(jsbtc.encodeBase58("00759d5f2b6d12712fef6f0f24c56804193e1aeac176c1faae"),
                "1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1");

        });
        it('decodeBase58',  () => {
            assert.equal(jsbtc.decodeBase58("1Bitapsw1aT8hkLXFtXwZQfHgNwNJEyJJ1"),
                "00759d5f2b6d12712fef6f0f24c56804193e1aeac176c1faae");
            assert.equal(jsbtc.encodeBase58(jsbtc.decodeBase58("11ju1bKJX8HGdT7YmKLi", {hex:false})),
                "11ju1bKJX8HGdT7YmKLi");
            assert.equal(jsbtc.encodeBase58(jsbtc.decodeBase58("11ju1bKJX8HGdT7YmKLi", {hex:true})),
                "11ju1bKJX8HGdT7YmKLi");
        });

    });

    describe("BIP38 mnemonic functions:", function(){
        it('Generate entropy',  () => {
            assert.equal(jsbtc.generate_entropy().length, 64);
            assert.equal(jsbtc.generate_entropy({strength: 224}).length, 56);
            assert.equal(jsbtc.generate_entropy({strength: 192}).length, 48);
            assert.equal(jsbtc.generate_entropy({strength: 160}).length, 40);
            assert.equal(jsbtc.generate_entropy({strength: 128}).length, 32);
        });
        it('igam and igamc math functions', function() {
           let q = 0.0000000000001;
           assert.equal(jsbtc.igam(0.56133437, 7.79533309) - 0.99989958147838275959 < q, true);
           assert.equal(jsbtc.igam(3.80398274, 0.77658461) - 0.01162079725209424867 < q, true);
           assert.equal(jsbtc.igam(6.71146614, 0.39790492) - 0.00000051486912406477 < q, true);
           assert.equal(jsbtc.igam(5.05505886, 6.08602125) - 0.71809645160316382118 < q, true);
           assert.equal(jsbtc.igam(9.45603411, 4.60043366) - 0.03112942473115925396 < q, true);
           assert.equal(jsbtc.igamc(3.08284045, 0.79469709) - 0.95896191705843125686 < q, true);
           assert.equal(jsbtc.igamc(7.91061495, 9.30889249) - 0.27834295370900602462 < q, true);
           assert.equal(jsbtc.igamc(4.89616780, 5.75314859) - 0.30291667399717547848 < q, true);
           assert.equal(jsbtc.igamc(8.11261940, 4.05857957) - 0.95010562492501993148 < q, true);
           assert.equal(jsbtc.igamc(1.34835811, 6.64708856) - 0.00295250273836756942 < q, true);
       });
    });

    describe("Private key functions:", function(){
        it('privateKeyToWif',  () => {
            assert.equal(jsbtc.privateKeyToWif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4"),
                                               'L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX');
            assert.equal(jsbtc.privateKeyToWif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                                               {compressed: true, testnet: false}),
                                               'L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX');
            assert.equal(jsbtc.privateKeyToWif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                                               {compressed: false, testnet: false}),
                                               '5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf');
            assert.equal(jsbtc.privateKeyToWif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                                                {compressed: true, testnet: true}),
                                                'cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6');
            assert.equal(jsbtc.privateKeyToWif("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4",
                                                {compressed: false, testnet: true}),
                                                '93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L');
            let m = jsbtc.tools.Buffer.from("ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4", 'hex');
            assert.equal(jsbtc.privateKeyToWif(m, {compressed: false, testnet: true}),
                                               '93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L');
        });

        it('createPrivateKey + wifToPrivateKey',  () => {
            let wk = jsbtc.createPrivateKey();
            let k = jsbtc.wifToPrivateKey(wk);
            assert.equal(jsbtc.privateKeyToWif(k),wk);
            wk = jsbtc.createPrivateKey({testnet: 1});
            k = jsbtc.wifToPrivateKey(wk);
            assert.equal(jsbtc.privateKeyToWif(k, {testnet: 1}),wk);
            wk = jsbtc.createPrivateKey({compressed: 0});
            k = jsbtc.wifToPrivateKey(wk);
            assert.equal(jsbtc.privateKeyToWif(k, {compressed: 0}),wk);
            wk = jsbtc.createPrivateKey({compressed: 0, testnet: 1});
            k = jsbtc.wifToPrivateKey(wk);
            assert.equal(jsbtc.privateKeyToWif(k, {compressed: 0, testnet: 1}),wk);
            wk = jsbtc.createPrivateKey({compressed: 0, testnet: 1, wif: 0});
            assert.equal((wk instanceof jsbtc.Buffer), true);
        });

        it('isWifValid',  () => {
            assert.equal(jsbtc.isWifValid("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX"), true);
            assert.equal(jsbtc.isWifValid("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf"), true);
            assert.equal(jsbtc.isWifValid("5KPPLXhtga99qqMcWRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf"), false);
            assert.equal(jsbtc.isWifValid("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L"), true);
            assert.equal(jsbtc.isWifValid("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6"), true);
            assert.equal(jsbtc.isWifValid("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6"), true);
            assert.equal(jsbtc.isWifValid("cUWo47X@YiyByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h6"), false);
            assert.equal(jsbtc.isWifValid("cUWo47XLYiyFByuFicFS3y4FAza3r3R5XA7Bm7wA3dgSKDYox7h9"), false);
            assert.equal(jsbtc.isWifValid(44), false);
        });

        it('privateToPublicKey',  () => {
            let priv = "ceda1ae4286015d45ec5147fe3f63e9377ccd6d4e98bcf0847df9937da1944a4";
            let pu = "04b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4c8cbe28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663";
            let pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.privateToPublicKey(priv), pk);
            assert.equal(jsbtc.privateToPublicKey(priv, {hex: true}), pk);
            assert.equal(jsbtc.privateToPublicKey(priv, {hex: false}).equals(jsbtc.Buffer.from(pk, 'hex')), true);
            assert.equal(jsbtc.privateToPublicKey(priv, {compressed: false}), pu);
            assert.equal(jsbtc.privateToPublicKey("L49obCXV7fGz2YRzLCSJgeZBYmGeBbKPT7xiehUeYX2S4URkPFZX"), pk);
            assert.equal(jsbtc.privateToPublicKey("5KPPLXhtga99qqMceRo4Z6LXV3Kx6a9hRx3ez2U7EwP5KZfy2Wf"), pu);
            assert.equal(jsbtc.privateToPublicKey("93A1vGXSGoDHotruGmgyRgtV8hgfFjgtmtuc4epcag886W9d44L"), pu);
            expect(() => jsbtc.privateToPublicKey(45)).to.throw('invalid');


        });

        it('isPublicKeyValid',  () => {
            let pu = "04b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4c8cbe28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663";
            let pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.isPublicKeyValid(pu), true);
            assert.equal(jsbtc.isPublicKeyValid(pk), true);
            assert.equal(jsbtc.isPublicKeyValid(jsbtc.Buffer.from(pu, 'hex')), true);
            assert.equal(jsbtc.isPublicKeyValid(jsbtc.Buffer.from(pk, 'hex')), true);
            pu = "63qdbdc16dbdf4bb9cf45b55e7d03e514fb04dcef34208155c7d3ec88e9045f4c8cbe28702911260f2a1da099a338bed4ee98f66bb8dba8031a76ab537ff6663";
            pk = "02b635dbdc16dbdf455bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.isPublicKeyValid(pu), false);
            assert.equal(jsbtc.isPublicKeyValid(pk), false);
            assert.equal(jsbtc.isPublicKeyValid("8798"), false);
        });
    });

    describe("Address functions:", function(){
        it('hashToAddress', () => {
            let OP = jsbtc.opcodes.OPCODE;
            let B = jsbtc.Buffer.from

            let pc = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
            let s = jsbtc.Buffer.concat([B([pc.length / 2]), B(pc, 'hex'), B([OP.OP_CHECKSIG])])
            let h = jsbtc.hash160(pc);
            assert.equal(jsbtc.hashToAddress(h), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            assert.equal(jsbtc.hashToAddress(h, {testnet: true}), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
            let pk = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            h = jsbtc.hash160(pk);
            assert.equal(jsbtc.hashToAddress(h, {witness_version: null}), "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1");
            assert.equal(jsbtc.hashToAddress(h, {witness_version: null, testnet: true}), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            assert.equal(jsbtc.hashToAddress(h, {witness_version: null, testnet: true, script_hash: true}), "2N87FX8HDDjrFTAuHSnoSo9cievn7uAM8rV");
            expect(() => jsbtc.hashToAddress(h.toString('hex') + "00")).to.throw('length incorrect');
            expect(() => jsbtc.hashToAddress(h.toString('hex') + "00",  {witness_version: null})).to.throw('length incorrect');

            assert.equal(jsbtc.hashToAddress(h, {testnet: true, witness_version: null}), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            let p = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff";
            pk = jsbtc.privateToPublicKey(p, {hex: false});
            let script = jsbtc.Buffer.concat([jsbtc.Buffer.from([0, 20]), jsbtc.hash160(pk)]);
            let script_hash = jsbtc.hash160(script);
            assert.equal(jsbtc.hashToAddress(script_hash, {testnet: false, script_hash: true, witness_version: null}),
                "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw");
            expect(() => jsbtc.hashToAddress("test non hex input")).to.throw('encoding required');

            let test = false;
            try {
                jsbtc.hashToAddress("test non hex input", {testnet: false, script_hash: true, witness_version: null})

            } catch (e) {
                test =true;
            }
            assert.equal(true, test);
            assert.equal(jsbtc.hashToAddress(script_hash.toString('hex'), {testnet: false, script_hash: true, witness_version: null}),
                "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw");

        });

        it('addressToHash', () => {
            let h = "751e76e8199196d454941c45d1b3a323f1433bd6";
            assert.equal(jsbtc.addressToHash("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", {hex: true}), h);
            assert.equal(jsbtc.addressToHash("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", {hex: true}), h);
            h  = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262";
            assert.equal(jsbtc.addressToHash("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", {hex: true}), h);
            h = "a307d67484911deee457779b17505cedd20e1fe9";
            assert.equal(jsbtc.addressToHash("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1", {hex: true}), h);
            assert.equal(jsbtc.addressToHash("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c", {hex: true}), h);
            h = "14c14c8d26acbea970757b78e6429ad05a6ac6bb";
            assert.equal(jsbtc.addressToHash("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw", {hex: true}), h);
            assert.equal(jsbtc.addressToHash("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", {hex: true}), h);

            expect(() => jsbtc.addressToHash(90)).to.throw('invalid');
            assert.equal(jsbtc.addressToHash("QM1u8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"),null);
        });

        it('publicKeyToAddress', () => {
            let cpub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
            expect(() => jsbtc.publicKeyToAddress("02qqbe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")).to.throw('encoding required');
            assert.equal(jsbtc.publicKeyToAddress(cpub), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            assert.equal(jsbtc.publicKeyToAddress(cpub, {testnet: true}), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
            assert.equal(jsbtc.publicKeyToAddress(jsbtc.Buffer.from(cpub, 'hex'), {testnet: true}), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
            cpub = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.publicKeyToAddress(cpub, {witness_version: null}), "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1");
            assert.equal(jsbtc.publicKeyToAddress(cpub, {witness_version: null, testnet: true}), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            let priv = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff";
            assert.equal(jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv), {p2sh_p2wpkh: true, witness_version: null}), "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw");
            expect(() => jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv, {compressed: false}), {p2sh_p2wpkh: true})).to.throw('length invalid');
            expect(() => jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv, {compressed: false}), {p2sh_p2wpkh: false, witness_version: 0})).to.throw('length invalid');
            expect(() => jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(cpub + "00", {compressed: false}))).to.throw('length invalid');
            priv = "5HrHm3Q2jUnvZPPKKDNkSSLoCqh5QyP7nvFGzHNxgw27ffPJjce";
            assert.equal(jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv), {witness_version: null}), "1HMkFegHBraqmvvX3FP9q2Q9CymB9T9y8g");

        });

        it('addressType', () => {
            assert.equal(jsbtc.addressType("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), 'P2WPKH');
            assert.equal(jsbtc.addressType("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), 'P2WPKH');
            assert.equal(jsbtc.addressType("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), 'P2WSH');
            assert.equal(jsbtc.addressType("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"), 'P2WSH');
            assert.equal(jsbtc.addressType("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"), 'P2PKH');
            assert.equal(jsbtc.addressType("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c"), 'P2PKH');
            assert.equal(jsbtc.addressType("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"), 'P2SH');
            assert.equal(jsbtc.addressType("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"), 'P2SH');
            assert.equal(jsbtc.addressType("rMu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"), 'NON_STANDARD');
            let C = jsbtc.constants.SCRIPT_TYPES
            assert.equal(jsbtc.addressType("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", {num: true}), C['P2WPKH']);
            assert.equal(jsbtc.addressType("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",  {num: true}), C['P2WPKH']);
            assert.equal(jsbtc.addressType("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",  {num: true}), C['P2WSH']);
            assert.equal(jsbtc.addressType("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",  {num: true}), C['P2WSH']);

            assert.equal(jsbtc.addressType("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1",  {num: true}), C['P2PKH']);
            assert.equal(jsbtc.addressType("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c",  {num: true}), C['P2PKH']);
            assert.equal(jsbtc.addressType("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw",  {num: true}), C['P2SH']);
            assert.equal(jsbtc.addressType("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", {num: true}), C['P2SH']);
            assert.equal(jsbtc.addressType("rMu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", {num: true}), C['NON_STANDARD']);
        });

        it('addressNetType', () => {
            assert.equal(jsbtc.addressNetType("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), 'mainnet');
            assert.equal(jsbtc.addressNetType("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), 'testnet');
            assert.equal(jsbtc.addressNetType("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), 'mainnet');
            assert.equal(jsbtc.addressNetType("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"), 'testnet');
            assert.equal(jsbtc.addressNetType("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"), 'mainnet');
            assert.equal(jsbtc.addressNetType("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c"), 'testnet');
            assert.equal(jsbtc.addressNetType("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"), 'mainnet');
            assert.equal(jsbtc.addressNetType("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"), 'testnet');
            assert.equal(jsbtc.addressNetType("rMu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh"), null);
        });

        it('addressToScript', () => {
            assert.equal(jsbtc.addressToScript("17rPqUf4Hqu6Lvpgfsavt1CzRy2GL19GD3", {'hex': true}),
                '76a9144b2832feeda5692c96c0594a6314136a998f515788ac');
            assert.equal(jsbtc.addressToScript("33RYUa9jT541UNPsKdV7V1DmwMiQHpVfD3", {'hex': true}),
                'a914130319921ecbcfa33fec2a8503c4ae1c86e4419387');
            assert.equal(jsbtc.addressToScript("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", {'hex': true}),
                '0014751e76e8199196d454941c45d1b3a323f1433bd6');
            assert.equal(jsbtc.addressToScript("17rPqUf4Hqu6Lvpgfsavt1CzRy2GL19GD3").toString('hex'),
                '76a9144b2832feeda5692c96c0594a6314136a998f515788ac');
            assert.equal(jsbtc.addressToScript("33RYUa9jT541UNPsKdV7V1DmwMiQHpVfD3").toString('hex'),
                'a914130319921ecbcfa33fec2a8503c4ae1c86e4419387');
            assert.equal(jsbtc.addressToScript("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").toString('hex'),
                '0014751e76e8199196d454941c45d1b3a323f1433bd6');
            expect(() => jsbtc.addressToScript("bd6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").toString('hex')).to.throw('address invalid');
            expect(() => jsbtc.addressToScript(45)).to.throw('address invalid');

        });

        it('getWitnessVersion', () => {
            assert.equal(jsbtc.getWitnessVersion("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), 0);
        });

        it('isAddressValid', () => {
            assert.equal(jsbtc.isAddressValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), true);
            assert.equal(jsbtc.isAddressValid("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", {testnet: true}), true);
            assert.equal(jsbtc.isAddressValid("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"), false);
            assert.equal(jsbtc.isAddressValid("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), true);
            assert.equal(jsbtc.isAddressValid("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", {testnet: true}), true);
            assert.equal(jsbtc.isAddressValid("1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1"), true);
            assert.equal(jsbtc.isAddressValid("mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c", {testnet: true}), true);
            assert.equal(jsbtc.isAddressValid("33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw"), true);
            assert.equal(jsbtc.isAddressValid(54), false);
            assert.equal(jsbtc.isAddressValid("33am12q3Bncnn3BfvLYHczyv23Sq2WWbwjw"), false);
            assert.equal(jsbtc.isAddressValid("2Mu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", {testnet: true}), true);
            assert.equal(jsbtc.isAddressValid("2Mu8y4mm4oF89yppDbUAAEwyBEPezrx7CLh"), false);
            assert.equal(jsbtc.isAddressValid("2Mu8y4mm4oF89yppDbUAAEwyBEPezrx7CCLh"), false);
            assert.equal(jsbtc.isAddressValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("tb1qw508d6qejxtdg4W5r3zarvary0c5xw7kxpjzsx", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("bc1qrp33g0q5c5txsp8arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), false);
            assert.equal(jsbtc.isAddressValid("TB1QRP23G0Q5C5TXSP9ARYSRX4K6ZDKFS4NCE4XJ0GDCCCEFVPYSXF3Q0SL5K7", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("TB1QRP23G0Q5C5TXSP9ARYSRX4K6ZDKFS4NCE4XJ0GDCCCEFVPYSXF3Q0sL5K7", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("tb1", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("tbqqrp23g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("1Fs2Xqrk4P2XADaJeZWykaGXJ2HEb6RyT1"), false);
            assert.equal(jsbtc.isAddressValid("mvNyptwisQTkwL3vN8VMaVUrA3swVCX83c", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("33am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw", {testnet: true}), false);
            assert.equal(jsbtc.isAddressValid("33am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw"), false);
            assert.equal(jsbtc.isAddressValid("73am12q3Bncmn3BfvLYHczyv23Sq2Wbwjw"), false);
            assert.equal(jsbtc.isAddressValid("2Mu8y4mm4oF78yppDbUAAEwyBEPezrx7CLh",  {testnet: true}), false);
        });
    });

    describe("Script functions:", function(){
        it('hashToScript', () => {
            let h = "751e76e8199196d454941c45d1b3a323f1433bd6";
            assert.equal(jsbtc.hashToScript(h, 0, {'hex': true}), '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac');
            assert.equal(jsbtc.hashToScript(h, 1, {'hex': true}), 'a914751e76e8199196d454941c45d1b3a323f1433bd687');
            assert.equal(jsbtc.hashToScript(h, 5, {'hex': true}), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
            assert.equal(jsbtc.hashToScript(h, 6, {'hex': true}), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
            assert.equal(jsbtc.hashToScript(h, 6).toString("hex"), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
            assert.equal(jsbtc.hashToScript(h, "P2PKH", {'hex': true}), '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac');
            assert.equal(jsbtc.hashToScript(h, "P2SH", {'hex': true}), 'a914751e76e8199196d454941c45d1b3a323f1433bd687');
            assert.equal(jsbtc.hashToScript(h, "P2WPKH", {'hex': true}), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
            expect(() => jsbtc.hashToScript(h, 90)).to.throw('unsupported script type');

        });
        it('publicKeyTo_P2SH_P2WPKH_Script', () => {
            let p = "0003b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            expect(() => jsbtc.publicKeyToP2SH_P2WPKHScript(p)).to.throw('public key len invalid');
            p = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.publicKeyToP2SH_P2WPKHScript(p, {hex: true}), "0014a307d67484911deee457779b17505cedd20e1fe9");
            assert.equal(jsbtc.publicKeyToP2SH_P2WPKHScript(p).toString('hex'),"0014a307d67484911deee457779b17505cedd20e1fe9");
        });
        it('publicKeyTo_PUBKEY_Script', () => {
            let p = "0338f42586b2d10fe2ad08c170750c9317a01e59563b9e322a943b8043c7f59380";
            let s = "210338f42586b2d10fe2ad08c170750c9317a01e59563b9e322a943b8043c7f59380ac";
            assert.equal(jsbtc.publicKeyTo_PUBKEY_Script(p, {hex: true}),s);
        });
        it('parseScript', () => {
            let O = jsbtc.opcodes.OPCODE;
            let H = jsbtc.tools.hexToBytes;
            let f = jsbtc.parseScript
            assert.equal(f([O.OP_RETURN, 0x00]).type, "NULL_DATA");
            assert.equal(f([O.OP_RETURN, 0x00]).data.toString('hex'), "");
            assert.equal(f([O.OP_RETURN].concat(H('203132333435363738393031323334353637383930313233343536373839303132'))).type,
                "NULL_DATA");
            assert.equal(f([O.OP_RETURN].concat(H('203132333435363738393031323334353637383930313233343536373839303132'))).data.toString('hex'),
                "3132333435363738393031323334353637383930313233343536373839303132");
            assert.equal(f([O.OP_RETURN].concat(H('2031323334353637383930313233343536373839303132333435363738393031323131'))).type,
                "NULL_DATA_NON_STANDARD");
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1, 0x00]).type, "NULL_DATA");
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1, 0x00]).data.toString('hex'), "");
            let k = H("203132333435363738393031323334353637383930313233343536373839303132");
            let r = "3132333435363738393031323334353637383930313233343536373839303132";
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1].concat(k)).type, "NULL_DATA");
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1].concat(k)).data.toString('hex'), r);
            k = H('2031323334353637383930313233343536373839303132333435363738393031323131');
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1].concat(k)).type, "NULL_DATA_NON_STANDARD");
            k = H('503132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930');
            r = '3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930';
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1].concat(k)).type, "NULL_DATA");
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1].concat(k)).data.toString('hex'), r);
            k = H('51313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031');
            assert.equal(f([O.OP_RETURN, O.OP_PUSHDATA1].concat(k)).type, "NULL_DATA_NON_STANDARD");
            let s = jsbtc.Buffer.from("a914546fbecb877edbe5777bc0ce4c8be6989d8edd9387",'hex');
            assert.equal(f(s).type, "P2SH");
            s = "a914546fbecb877edbe5777bc0ce4c8be6989d8edd9387";
            assert.equal(f(s).nType, 1);
            assert.equal(f(s).addressHash.toString('hex'), '546fbecb877edbe5777bc0ce4c8be6989d8edd93');
            assert.equal(f(s).reqSigs, null);
            s = "76a9143053ef41e2106fb5fea261c8ee3fd44f007b5ee688ac";
            assert.equal(f(s).type, "P2PKH");
            assert.equal(f(s).nType, 0);
            assert.equal(f(s).reqSigs, 1);
            assert.equal(f(s).addressHash.toString('hex'), '3053ef41e2106fb5fea261c8ee3fd44f007b5ee6');
            s = "410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac";
            assert.equal(f(s).type, "PUBKEY");
            assert.equal(f(s).nType, 2);
            assert.equal(f(s).reqSigs, 1);
            assert.equal(f(s).addressHash.toString('hex'), '119b098e2e980a229e139a9ed01a469e518e6f26');
            s = "00142ac50173769ba101bb2a2e7b32f158eb8c77d8a4";
            assert.equal(f(s).type, "P2WPKH");
            assert.equal(f(s).nType, 5);
            assert.equal(f(s).reqSigs, 1);
            assert.equal(f(s).addressHash.toString('hex'), '2ac50173769ba101bb2a2e7b32f158eb8c77d8a4');
            s = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d";
            assert.equal(f(s).type, "P2WSH");
            assert.equal(f(s).nType, 6);
            assert.equal(f(s).reqSigs, null);
            assert.equal(f(s).addressHash.toString('hex'), '701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d')

            s = "512102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623";
            s +="441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf";
            s +="410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060";
            s +="466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97";
            s +="40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e3953ae";
            assert.equal(f(s).type, "MULTISIG");
            assert.equal(f(s).nType, 4);
            assert.equal(f(s).reqSigs, 1);

            s = "5f210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c";
            s +="715fae";
            assert.equal(f(s).type, "MULTISIG");
            assert.equal(f(s).nType, 4);
            assert.equal(f(s).reqSigs, 15);
            s = "0114410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc34550114ae";

            assert.equal(f(s).type, "NON_STANDARD");
            assert.equal(f(s).nType, 7);
            assert.equal(f(s).reqSigs, 20);
        });
        it('scriptToAddress', () => {
            assert.equal(jsbtc.scriptToAddress("76a914f18e5346e6efe17246306ce82f11ca53542fe00388ac"),
                "1P2EMAeiSJEfCrtjC6ovdWaGWW1Mb6azpX");
            assert.equal(jsbtc.scriptToAddress("a9143f4eecba122ad73039d481c8d37f99cb4f887cd887"),
                "37Tm3Qz8Zw2VJrheUUhArDAoq58S6YrS3g");
            assert.equal(jsbtc.scriptToAddress("76a914a307d67484911deee457779b17505cedd20e1fe988ac", {testnet: true}),
                "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            assert.equal(jsbtc.scriptToAddress("0014751e76e8199196d454941c45d1b3a323f1433bd6"),
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            assert.equal(jsbtc.scriptToAddress("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"),
                "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej");
        });
        it('decodeScript', () => {
            assert.equal(jsbtc.decodeScript('76a9143520dd524f6ca66f63182bb23efff6cc8ee3ee6388ac'),
               "OP_DUP OP_HASH160 [20] OP_EQUALVERIFY OP_CHECKSIG");
            assert.equal(jsbtc.decodeScript('76a9143520dd524f6ca66f63182bb23efff6cc8ee3ee6388ac', {asm: true}),
                "OP_DUP OP_HASH160 OP_PUSHBYTES[20] 3520dd524f6ca66f63182bb23efff6cc8ee3ee63 OP_EQUALVERIFY OP_CHECKSIG");
            assert.equal(jsbtc.decodeScript('a91469f37572ab1b69f304f987b119e2450e0b71bf5c87'),
                "OP_HASH160 [20] OP_EQUAL");
            assert.equal(jsbtc.decodeScript('a91469f37572ab1b69f304f987b119e2450e0b71bf5c87', {asm: true}),
                "OP_HASH160 OP_PUSHBYTES[20] 69f37572ab1b69f304f987b119e2450e0b71bf5c OP_EQUAL");

            assert.equal(jsbtc.decodeScript('6a144279b52d6ee8393a9a755e8c6f633b5dd034bd67'),
                "OP_RETURN [20]");
            assert.equal(jsbtc.decodeScript('6a144279b52d6ee8393a9a755e8c6f633b5dd034bd67', {asm: true}),
                "OP_RETURN OP_PUSHBYTES[20] 4279b52d6ee8393a9a755e8c6f633b5dd034bd67");
            let s = "6a4c51000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            assert.equal(jsbtc.decodeScript(s, ),"OP_RETURN OP_PUSHDATA1 [81]");
            assert.equal(jsbtc.decodeScript(s, {asm:true}),"OP_RETURN OP_PUSHDATA1[81] 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
            s = "5f210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c715fae"
            assert.equal(jsbtc.decodeScript(s, ),"OP_15 [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] OP_15 OP_CHECKMULTISIG");
            assert.equal(jsbtc.decodeScript(s, {asm: true}),'OP_15 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_15 OP_CHECKMULTISIG');
            assert.equal(jsbtc.decodeScript('00144160bb1870159a08724557f75c7bb665a3a132e0', ),"OP_0 [20]");
            assert.equal(jsbtc.decodeScript('0020cdbf909e935c855d3e8d1b61aeb9c5e3c03ae8021b286839b1a72f2e48fdba70', ),"OP_0 [32]");

        });
        it('signMessage', () => {
            let s = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb";
            assert.equal(jsbtc.signMessage("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
                "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf", {hex: true}).signature, s);
            assert.equal(jsbtc.signMessage("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
                "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf", {hex: true}).recId, 0);

      });
        it('verifySignature', () => {
            let p = "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf";
            let s = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb";
            let msg = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";
            assert.equal(jsbtc.verifySignature(s, jsbtc.privateToPublicKey(p), msg), true);

            let priv = "7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76";

            s = jsbtc.signMessage(msg, priv, {hex: true}).signature;
            assert.equal(s, "304402202c843bd163b57910bff132cf84ef32c65b4ea1abefa8810accb6f1ace677078b0220338fe888b4165a187cbb7f882b6b099e63d99e25e0a6bdf2917665f9f66ea77f");
            assert.equal(jsbtc.verifySignature(s, jsbtc.privateToPublicKey(priv), msg), true);
        });
        it('publicKeyRecovery', () => {
            let s = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb";
            assert.equal(jsbtc.signMessage("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
                "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf", {hex: true}).signature, s);


            let p = "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf";
            s = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb";
            let msg = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";
            let r = jsbtc.signMessage("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
                "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf", {hex: true}).recId;
            assert.equal(jsbtc.publicKeyRecovery(s, msg, r, {hex: true}), jsbtc.privateToPublicKey(p, {hex: true}));
        });
    });


    describe("Address classes:", function(){
        it('hashToScript', () => {
            let h = "7B56E2B7BD189F4491D43A1D209E6268046DF1741F61B6397349D7AA54978E76";
            assert.equal(new jsbtc.PrivateKey(h, {'compressed': true, testnet: false}).wif,
                'L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4');

            assert.equal(new jsbtc.PrivateKey(h, {'compressed': false, testnet: false}).wif,
                '5Jkc7xqsrqA5pGQdwDHSQXRV3pUBLTXVjBjqJUSVz3pUmyuAFwP');

            assert.equal(new jsbtc.PrivateKey(h, {'compressed': true, testnet: true}).wif,
                'cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv');

            assert.equal(new jsbtc.PrivateKey(h, {'compressed': false, testnet: true}).wif,
                '92XEhhfRT4EDnKuvZZBMH7yShUptVd4h58bnP6o1KnZXYzkVa55');

            assert.equal(new jsbtc.PrivateKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4",
                                             {'compressed': false, testnet: true}).wif,
                'L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4');

            let cpk = "02a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4";
            let ucpk = "04a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb43bbd96a641808e5f34eb568e804fe679de82de419e2512736ea09013a82324a6"

            assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
                {'compressed': false}).hex, ucpk);
            assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
                {'compressed': false}).key.toString('hex'), ucpk);
            assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
                {'compressed': false}).compressed, false);
            assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
                {'compressed': false}).testnet, false);
            assert.equal(new jsbtc.PublicKey(Buffer.from("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76", 'hex'),
                {'compressed': false}).compressed, false);

            assert.equal(new jsbtc.PublicKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4",
                {'compressed': true}).hex, cpk);
            assert.equal(new jsbtc.PublicKey("L1MU1jUjUwZ6Fd1L2HDZ8qH4oSWxct5boCQ4C87YvoSZbTW41hg4",
                {'compressed': false}).hex, cpk);

            assert.equal(new jsbtc.PublicKey(ucpk).key.toString('hex'), ucpk);
            assert.equal(new jsbtc.PublicKey(cpk).key.toString('hex'), cpk);
            assert.equal(new jsbtc.PublicKey(ucpk, {compressed: true}).key.hex(), ucpk);
            // assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
            //     {'compressed': true}).compressed, false);
            // assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
            //     {'compressed': true}).testnet, false);
            // assert.equal(new jsbtc.PublicKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76",
            //     {'compressed': true, testnet: true}).testnet, true);
        });

    });

});

