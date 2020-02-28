#ifndef __HMAC_H__
#define __HMAC_H__

#include <stdint.h>
#include "sha512.h"

typedef struct _HMAC_SHA512_CTX {
	uint8_t o_key_pad[SHA512_BLOCK_LENGTH];
	SHA512_CTX ctx;
} HMAC_SHA512_CTX;

#ifdef __cplusplus
extern "C"
{
#endif

void hmac_sha512_Init(HMAC_SHA512_CTX *hctx, const uint8_t *key, const uint32_t keylen);
void hmac_sha512_Update(HMAC_SHA512_CTX *hctx, const uint8_t *msg, const uint32_t msglen);
void hmac_sha512_Final(HMAC_SHA512_CTX *hctx, uint8_t *hmac);
void hmac_sha512_oneline(const uint8_t *key, const uint32_t keylen, const uint8_t *msg, const uint32_t msglen, uint8_t *hmac);
void hmac_sha512_prepare(const uint8_t *key, const uint32_t keylen, uint64_t *opad_digest, uint64_t *ipad_digest);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif