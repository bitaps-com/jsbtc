#!/bin/bash
rm /jsbtc/src/btc_crypto.*  2> /dev/null
cd /root/emsdk;

source /root/emsdk/emsdk_env.sh;

set -e

export OPTIMIZE="-Oz"
export LDFLAGS="${OPTIMIZE}"
export CFLAGS="${OPTIMIZE}"
export CXXFLAGS="${OPTIMIZE}"

echo "============================================="
echo "Compiling wasm bindings"
echo "============================================="

cd /jsbtc/secp256k1
# authgen.sh
sh autogen.sh
# configure secp256k1
emconfigure ./configure --enable-module-recovery
# make secp256k1
emmake make



(
    emcc \
    ${OPTIMIZE} \
     -s WASM=1  \
     -s "ENVIRONMENT='web,node'" \
     -s NO_EXIT_RUNTIME=1 \
     -s INLINING_LIMIT=1 \
     -s FILESYSTEM=0 \
     -s MODULARIZE=1 \
     -s NO_DYNAMIC_EXECUTION=0 \
     -s STRICT=1 \
     --closure 1 \
     -s NO_FILESYSTEM=1 \
     -s LINKABLE=0 \
     -s BINARYEN_IGNORE_IMPLICIT_TRAPS=1 \
     -std=c++1z \
    -s ALLOW_MEMORY_GROWTH=0 \
    -s INVOKE_RUN=1 \
    -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
    -s EXPORTED_FUNCTIONS="['_malloc', '_free','_secp256k1_ec_pubkey_create', '_secp256k1_context_randomize', '_secp256k1_context_create', '_secp256k1_context_destroy', '_secp256k1_ecdsa_recoverable_signature_parse_compact', '_secp256k1_ecdsa_recover', '_secp256k1_ec_pubkey_serialize', '_secp256k1_ecdsa_signature_parse_compact', '_secp256k1_ec_pubkey_parse', '_secp256k1_ecdsa_verify', '_secp256k1_ecdsa_sign_recoverable', '_secp256k1_ec_seckey_verify', '_secp256k1_ecdsa_recoverable_signature_serialize_compact']" \
    -s EXPORTED_RUNTIME_METHODS='["getValue"]' \
    -s SINGLE_FILE=1 \
     -o /jsbtc/src/btc_crypto.js \
     /jsbtc/btc-crypto/sha256.cpp \
     /jsbtc/btc-crypto/siphash.cpp \
     /jsbtc/btc-crypto/uint256.cpp \
     /jsbtc/btc-crypto/base58.cpp \
     /jsbtc/btc-crypto/ripemd160.cpp \
     /jsbtc/secp256k1/.libs/libsecp256k1.a


)

echo "============================================="
echo "Compiling wasm bindings done"
echo "============================================="