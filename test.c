#include <assert.h>
#include <stdio.h>

#include "gost.h"

#define ASSERT32_EQ(a, b)               \
    do {                                \
        if (a != b) {                   \
            printf("%x != %x\n", a, b); \
        }                               \
    } while (0)

#define ASSERT64_EQ(a, b)                 \
    do {                                  \
        if (a != b) {                     \
            printf("%lx != %lx\n", a, b); \
        }                                 \
    } while (0)

#define ASSERT_CORRECT(key, text)          \
    do {                                   \
        GOST_ctx ctx;                      \
        uint64_t buf = text;               \
        GOST_init(&ctx, key);              \
        GOST_encrypt(&ctx, 1, &buf, &buf); \
        GOST_decrypt(&ctx, 1, &buf, &buf); \
        ASSERT64_EQ(buf, text);            \
    } while (0)

uint32_t key[8] = {0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff};

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

uint32_t t(uint32_t a) {
    uint32_t res = 0;
    for (int i = 7; i >= 0; i--) {
        res = res << 4;
        res |= sbox[i][(a >> i * 4) & 0xF];
    }
    return res;
}

uint32_t g(uint32_t k, uint32_t a) {
    return ROTL_11(t(a + k));
}

void test_t() {
    ASSERT32_EQ(t(0xfdb97531), 0x2a196f34);
    ASSERT32_EQ(t(0x2a196f34), 0xebd9f03a);
    ASSERT32_EQ(t(0xebd9f03a), 0xb039bb3d);
    ASSERT32_EQ(t(0xb039bb3d), 0x68695433);
}

void test_g() {
    ASSERT32_EQ(g(0x87654321, 0xfedcba98), 0xfdcbc20c);
    ASSERT32_EQ(g(0xfdcbc20c, 0x87654321), 0x7e791a4b);
    ASSERT32_EQ(g(0x7e791a4b, 0xfdcbc20c), 0xc76549ec);
    ASSERT32_EQ(g(0xc76549ec, 0x7e791a4b), 0x9791c849);
}

void test_correctness() {
    char *ptr = "cafebabecafebabecafebabecafebab";
    ASSERT_CORRECT(ptr, (uint64_t)0xcafebabe);
    ASSERT_CORRECT(ptr, (uint64_t)0x0);
    ASSERT_CORRECT(ptr, (uint64_t)0xFFFFFFFFFFFFFFFF);
    ASSERT_CORRECT(ptr, (uint64_t)0xdeadbeefdeadbeef);
}

int main() {
    test_t();
    test_g();
    test_correctness();

    GOST_CBC_ctx ctx;
    uint64_t plain[2] = {0xf000f000, 0xf000f000};
    uint64_t cipher[2];
    uint64_t iv = 0xcafecafe;

    GOST_CBC_init(&ctx,"cafebabecafebabecafebabecafebab", iv);
    GOST_CBC_encrypt(&ctx, 2, cipher, plain);
    GOST_CBC_decrypt(&ctx, 2, plain, cipher);

    printf("IV: %lx\n", iv);
    printf("Plain,Cipher\n");
    printf("%lx,%lx\n", cipher[0], cipher[1]);
    printf("%lx,%lx\n", plain[0], plain[1]);
}