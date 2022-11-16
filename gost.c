#include "gost.h"

static uint8_t sbox[8][16] = {
    {0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1},
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF},
    {0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0},
    {0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB},
    {0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC},
    {0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0},
    {0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7},
    {0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2},
};

// Expands key to the entire 32 cycle key schedule
void expand_key(uint32_t* src_key, uint32_t* key_sched) {
    size_t i = 0;
    size_t j = 1;
    while (i < 32) {
        if (i < 24) {
            key_sched[i] = src_key[i % 8];
            i++;
        } else {
            key_sched[i] = src_key[(i - j) % 8];
            i++;
            j += 2;
        }
    }
}

// Performs one round of encryption
uint32_t do_round(uint32_t round_key, uint32_t lhs, uint32_t rhs) {
    // Add the round key
    uint32_t key_added = round_key + rhs;

    // Perform substitution using the s boxes
    uint32_t s_boxed = 0;
    for (int i = 7; i >= 0; i--) {
        s_boxed = s_boxed << 4;
        s_boxed |= sbox[i][(key_added >> i * 4) & 0xF];
    }

    // Rotate left by 11
    uint32_t rotated = ROTL_11(s_boxed);

    // Xor with the left side of feistel network
    uint32_t xored = rotated ^ lhs;

    // Return result
    return xored;
}

void encrypt(uint32_t* key, uint64_t* cipher, uint64_t* plain) {
    // Expand the key to a full schedule
    uint32_t key_expand[32];
    expand_key(key, key_expand);

    // Split ciphertext into left and right side
    uint32_t lhs = (*plain >> 32) & 0xFFFFFFFF;
    uint32_t rhs = *plain & 0xFFFFFFFF;
    uint32_t swap_var;

    // Encrypt for 32 rounds
    for (size_t i = 0; i < 32; i++) {
        swap_var = do_round(key_expand[i], lhs, rhs);
        lhs = rhs;
        rhs = swap_var;
    }

    *cipher = ((uint64_t)lhs & 0xFFFFFFFF) | ((uint64_t)rhs << 32);
}

void decrypt(uint32_t* key, uint64_t* plain, uint64_t* cipher) {
    // Expand the key to a full schedule
    uint32_t key_expand[32];
    expand_key(key, key_expand);

    // Split ciphertext into left and right side
    uint32_t lhs = (*cipher >> 32) & 0xFFFFFFFF;
    uint32_t rhs = *cipher & 0xFFFFFFFF;
    uint32_t swap_var;

    // Decrypt for 32 rounds
    for (int i = 31; i >= 0; i--) {
        swap_var = do_round(key_expand[i], lhs, rhs);
        lhs = rhs;
        rhs = swap_var;
    }

    *plain = ((uint64_t)lhs & 0xFFFFFFFF) | ((uint64_t)rhs << 32);
}

void GOST_init(GOST_ctx* ctx, const unsigned char* key) {
    expand_key(key, ctx->rk);
}

void GOST_encrypt(const GOST_ctx* ctx, size_t blocks, uint64_t* cipher, uint64_t* plain) {
    while (blocks--) {
        encrypt(ctx->rk, cipher, plain);
        cipher++;
        plain++;
    }
}

void GOST_decrypt(const GOST_ctx* ctx, size_t blocks, uint64_t* plain, uint64_t* cipher) {
    while (blocks--) {
        decrypt(ctx->rk, cipher, plain);
        cipher++;
        plain++;
    }
}

void GOST_CBC_init(GOST_CBC_ctx* ctx, const unsigned char* key, uint64_t iv) {
    expand_key(key, ctx->ctx.rk);
    ctx->iv = iv;
}

void GOST_CBC_encrypt(GOST_CBC_ctx* ctx, size_t blocks, uint64_t* cipher, uint64_t* plain) {
    size_t i;
    uint64_t iv = ctx->iv;
    uint64_t buf;
    for (i = 0; i < blocks; i++) {
        iv = *plain ^ iv;
        encrypt(ctx->ctx.rk, cipher, &iv);
        ctx->iv = *cipher;
        plain++;
        cipher++;
    }
}

void GOST_CBC_decrypt(GOST_CBC_ctx* ctx, size_t blocks, uint64_t* cipher, uint64_t* plain) {
    size_t i;
    uint64_t iv = ctx->iv;
    uint64_t next_iv;
    for (i = 0; i < blocks; i++) {
        next_iv = *cipher;
        decrypt(ctx->ctx.rk, plain, &iv);
        *plain ^= iv;
        iv = next_iv;
        plain++;
        cipher++;
    }
}
