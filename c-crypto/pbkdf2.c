#include <string.h>
#include "pbkdf2.h"
#include "hmac.h"
#include "sha512.h"
#include "memzero.h"


void pbkdf2_hmac_sha512_Init(PBKDF2_HMAC_SHA512_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t blocknr)
{
	SHA512_CTX ctx;
#if BYTE_ORDER == LITTLE_ENDIAN
	REVERSE32(blocknr, blocknr);
#endif

	hmac_sha512_prepare(pass, passlen, pctx->odig, pctx->idig);
	memzero(pctx->g, sizeof(pctx->g));
	pctx->g[8] = 0x8000000000000000;
	pctx->g[15] = (SHA512_BLOCK_LENGTH + SHA512_DIGEST_LENGTH) * 8;

	memcpy (ctx.state, pctx->idig, sizeof(pctx->idig));
	ctx.bitcount[0] = SHA512_BLOCK_LENGTH * 8;
	ctx.bitcount[1] = 0;
	sha512_Update(&ctx, salt, saltlen);
	sha512_Update(&ctx, (uint8_t*)&blocknr, sizeof(blocknr));
	sha512_Final(&ctx, (uint8_t*)pctx->g);
#if BYTE_ORDER == LITTLE_ENDIAN
	for (uint32_t k = 0; k < SHA512_DIGEST_LENGTH / sizeof(uint64_t); k++) {
		REVERSE64(pctx->g[k], pctx->g[k]);
	}
#endif
	sha512_Transform(pctx->odig, pctx->g, pctx->g);
	memcpy(pctx->f, pctx->g, SHA512_DIGEST_LENGTH);
	pctx->first = 1;
}

void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX *pctx, uint32_t iterations)
{
	for (uint32_t i = pctx->first; i < iterations; i++) {
		sha512_Transform(pctx->idig, pctx->g, pctx->g);
		sha512_Transform(pctx->odig, pctx->g, pctx->g);
		for (uint32_t j = 0; j < SHA512_DIGEST_LENGTH / sizeof(uint64_t); j++) {
			pctx->f[j] ^= pctx->g[j];
		}
	}
	pctx->first = 0;
}

void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX *pctx, uint8_t *key)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	for (uint32_t k = 0; k < SHA512_DIGEST_LENGTH/sizeof(uint64_t); k++) {
		REVERSE64(pctx->f[k], pctx->f[k]);
	}
#endif
	memcpy(key, pctx->f, SHA512_DIGEST_LENGTH);
	memzero(pctx, sizeof(PBKDF2_HMAC_SHA512_CTX));
}

void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key, int keylen)
{
	uint32_t last_block_size = keylen % SHA512_DIGEST_LENGTH;
	uint32_t blocks_count = keylen / SHA512_DIGEST_LENGTH;
	if (last_block_size) {
		blocks_count++;
	} else {
		last_block_size = SHA512_DIGEST_LENGTH;
	}
	for (uint32_t blocknr = 1; blocknr <= blocks_count; blocknr++) {
		PBKDF2_HMAC_SHA512_CTX pctx;
		pbkdf2_hmac_sha512_Init(&pctx, pass, passlen, salt, saltlen, blocknr);
		pbkdf2_hmac_sha512_Update(&pctx, iterations);
		uint8_t digest[SHA512_DIGEST_LENGTH];
		pbkdf2_hmac_sha512_Final(&pctx, digest);
		uint32_t key_offset = (blocknr - 1) * SHA512_DIGEST_LENGTH;
		if (blocknr < blocks_count) {
			memcpy(key + key_offset, digest, SHA512_DIGEST_LENGTH);
		} else {
			memcpy(key + key_offset, digest, last_block_size);
		}
	}
}