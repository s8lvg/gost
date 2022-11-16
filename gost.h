#ifndef GOST_H
#define GOST_H

#include <stdint.h>
#include <stdio.h>

#define ROTL_11(val) (val << 11) | (val >> 21)

typedef struct {
    uint32_t rk[32];
} GOST_ctx;

typedef struct {
    GOST_ctx ctx;
    uint64_t iv;
} GOST_CBC_ctx;

void GOST_init(GOST_ctx* ctx, const unsigned char* key);
void GOST_encrypt(const GOST_ctx* ctx, size_t blocks, uint64_t* cipher, uint64_t* plain);
void GOST_decrypt(const GOST_ctx* ctx, size_t blocks, uint64_t* plain, uint64_t* cipher);

void GOST_CBC_init(GOST_CBC_ctx* ctx, const unsigned char* key16, uint64_t iv);
void GOST_CBC_encrypt(GOST_CBC_ctx* ctx, size_t blocks, uint64_t* cipher, uint64_t* plain);
void GOST_CBC_decrypt(GOST_CBC_ctx* ctx, size_t blocks, uint64_t* plain, uint64_t* cipher);

#endif /* GOST_H */
