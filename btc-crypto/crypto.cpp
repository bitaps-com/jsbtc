
#include <emscripten.h>
#include "sha256.h"
#include "base58.h"

extern "C" {

    EMSCRIPTEN_KEEPALIVE
    void crypto_sha256(const unsigned char* data, size_t len, unsigned char* out_data) {
        CSHA256().Write(data, len).Finalize(out_data);
    }

}