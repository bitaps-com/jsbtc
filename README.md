# jsbtc

[![travis build](https://img.shields.io/travis/bitaps-com/jsbtc?style=plastic)](https://github.com/bitaps-com/jsbtc)
[![codecov coverage](https://img.shields.io/codecov/c/github/bitaps-com/jsbtc/beta?style=plastic)](https://github.com/bitaps-com/jsbtc)
[![version](https://img.shields.io/npm/v/jsbitcoin/beta?style=plastic)](https://www.npmjs.com/package/jsbitcoin/v/1.0.0-beta.1)


JavaScript Bitcoin library


./autogen.sh

emconfigure ./configure --enable-module-recovery CFLAGS="-O3"
emmake make FORMAT=wasm


emcc src/libsecp256k1_la-secp256k1.o \
  -O3 \
  -s WASM=1 \
  -s BINARYEN_IGNORE_IMPLICIT_TRAPS=1 \
  -s "BINARYEN_TRAP_MODE='clamp'" \
  -s NO_FILESYSTEM=1 \
  -s MODULARIZE=1 \
  -s NO_EXIT_RUNTIME=1 \
  -s "EXPORT_NAME='SECP256K1'" \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s INVOKE_RUN=1 \
  -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
  -s NO_DYNAMIC_EXECUTION=1 \
  -s STRICT=1 \
  -s LINKABLE=1 \
  -s EXPORTED_RUNTIME_METHODS='["getValue"]' \
  -s EXPORTED_FUNCTIONS='[
  "_malloc",
  "_free",
  "_secp256k1_context_create",
  "_secp256k1_context_randomize",
  "_secp256k1_ec_seckey_verify",
  "_secp256k1_ec_privkey_tweak_add",
  "_secp256k1_ec_privkey_tweak_mul",
  "_secp256k1_ec_pubkey_create",
  "_secp256k1_ec_pubkey_parse",
  "_secp256k1_ec_pubkey_serialize",
  "_secp256k1_ec_pubkey_tweak_add",
  "_secp256k1_ec_pubkey_tweak_mul",
  "_secp256k1_ecdsa_recover",
  "_secp256k1_ecdsa_recoverable_signature_serialize_compact",
  "_secp256k1_ecdsa_recoverable_signature_parse_compact",
  "_secp256k1_ecdsa_sign",
  "_secp256k1_ecdsa_signature_malleate",
  "_secp256k1_ecdsa_signature_normalize",
  "_secp256k1_ecdsa_signature_parse_der",
  "_secp256k1_ecdsa_signature_parse_compact",
  "_secp256k1_ecdsa_signature_serialize_der",
  "_secp256k1_ecdsa_signature_serialize_compact",
  "_secp256k1_ecdsa_sign_recoverable",
  "_secp256k1_ecdsa_verify"]' \
  -o /out/secp256k1.js



  -O3 \
  -s WASM=1 \
  -s BINARYEN_IGNORE_IMPLICIT_TRAPS=1 \
  -s "BINARYEN_TRAP_MODE='clamp'" \
  -s NO_FILESYSTEM=1 \
  -s MODULARIZE=1 \
  -s NO_EXIT_RUNTIME=1 \
  -s "EXPORT_NAME='CRYPTO'" \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s INVOKE_RUN=1 \
  -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
  -s NO_DYNAMIC_EXECUTION=1 \
  -s STRICT=1 \
  -s LINKABLE=1 \
  -s EXPORTED_RUNTIME_METHODS='["getValue"]' \
  -s EXPORTED_FUNCTIONS='["_MapIntoRange"]' \