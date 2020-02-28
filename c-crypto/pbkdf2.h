#ifndef __PBKDF2_H__
#define __PBKDF2_H__

#include <stdint.h>
#include "sha512.h"

typedef struct _PBKDF2_HMAC_SHA512_CTX {
	uint64_t odig[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
	uint64_t idig[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
	uint64_t f[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
	uint64_t g[SHA512_BLOCK_LENGTH / sizeof(uint64_t)];
	char first;
} PBKDF2_HMAC_SHA512_CTX;

void pbkdf2_hmac_sha512_Init(PBKDF2_HMAC_SHA512_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t blocknr);
void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX *pctx, uint32_t iterations);
void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX *pctx, uint8_t *key);
void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key, int keylen);

#endif