try {
    var jsbtc = require('../src/jsbtc.js');
    var chai = require('chai');
    chai.use(require("chai-as-promised"));
} catch (e) {
    console.log(e);
}


const assert = chai.assert;
const expect = chai.expect;

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
            assert.equal(jsbtc.hashToAddress(h, {witness_version: NaN}), "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1");
            assert.equal(jsbtc.hashToAddress(h, {witness_version: NaN, testnet: true}), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            assert.equal(jsbtc.hashToAddress(h, {witness_version: NaN, testnet: true, script_hash: true}), "2N87FX8HDDjrFTAuHSnoSo9cievn7uAM8rV");
            expect(() => jsbtc.hashToAddress(h.toString('hex') + "00")).to.throw('length incorrect');
            expect(() => jsbtc.hashToAddress(h.toString('hex') + "00",  {witness_version: NaN})).to.throw('length incorrect');

            assert.equal(jsbtc.hashToAddress(h, {testnet: true, witness_version: NaN}), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            let p = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff";
            pk = jsbtc.privateToPublicKey(p, {hex: false});
            let script = jsbtc.Buffer.concat([jsbtc.Buffer.from([0, 20]), jsbtc.hash160(pk)]);
            let script_hash = jsbtc.hash160(script);
            assert.equal(jsbtc.hashToAddress(script_hash, {testnet: false, script_hash: true, witness_version: NaN}),
                "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw");
            expect(() => jsbtc.hashToAddress("test non hex input")).to.throw('encoding required');

            let test = false;
            try {
                jsbtc.hashToAddress("test non hex input", {testnet: false, script_hash: true, witness_version: NaN})

            } catch (e) {
                test =true;
            }
            assert.equal(true, test);
            assert.equal(jsbtc.hashToAddress(script_hash.toString('hex'), {testnet: false, script_hash: true, witness_version: NaN}),
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
            expect(jsbtc.addressToHash("QM1u8y4mm4oF88yppDbUAAEwyBEPezrx7CLh", {hex: true})).to.be.NaN;
        });

        it('publicKeyToAddress', () => {
            let cpub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
            expect(() => jsbtc.publicKeyToAddress("02qqbe667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")).to.throw('encoding required');
            assert.equal(jsbtc.publicKeyToAddress(cpub), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
            assert.equal(jsbtc.publicKeyToAddress(cpub, {testnet: true}), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
            assert.equal(jsbtc.publicKeyToAddress(jsbtc.Buffer.from(cpub, 'hex'), {testnet: true}), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
            cpub = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.publicKeyToAddress(cpub, {witness_version: NaN}), "1Fs2Xqrk4P2XADaJeZWykaGXJ4HEb6RyT1");
            assert.equal(jsbtc.publicKeyToAddress(cpub, {witness_version: NaN, testnet: true}), "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c");
            let priv = "L32a8Mo1LgvjrVDbzcc3NkuUfkpoLsf2Y2oEWkV4t1KpQdFzuyff";
            assert.equal(jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv), {p2sh_p2wpkh: true, witness_version: NaN}), "33am12q3Bncnn3BfvLYHczyv23Sq2Wbwjw");
            expect(() => jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv, {compressed: false}), {p2sh_p2wpkh: true})).to.throw('length invalid');
            expect(() => jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv, {compressed: false}), {p2sh_p2wpkh: false, witness_version: 0})).to.throw('length invalid');
            expect(() => jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(cpub + "00", {compressed: false}))).to.throw('length invalid');
            priv = "5HrHm3Q2jUnvZPPKKDNkSSLoCqh5QyP7nvFGzHNxgw27ffPJjce";
            assert.equal(jsbtc.publicKeyToAddress(jsbtc.privateToPublicKey(priv), {witness_version: NaN}), "1HMkFegHBraqmvvX3FP9q2Q9CymB9T9y8g");

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
            expect(jsbtc.addressNetType("rMu8y4mm4oF88yppDbUAAEwyBEPezrx7CLh")).to.be.NaN;
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

        it('publicKeyToP2SH_P2WPKHScript', () => {
            let p = "0003b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            expect(() => jsbtc.publicKeyToP2SH_P2WPKHScript(p)).to.throw('public key len invalid');
            p = "03b635dbdc16dbdf4bb9cf5b55e7d03e514fb04dcef34208155c7d3ec88e9045f4";
            assert.equal(jsbtc.publicKeyToP2SH_P2WPKHScript(p, {hex: true}), "0014a307d67484911deee457779b17505cedd20e1fe9");
            assert.equal(jsbtc.publicKeyToP2SH_P2WPKHScript(p).toString('hex'),"0014a307d67484911deee457779b17505cedd20e1fe9");
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


});

