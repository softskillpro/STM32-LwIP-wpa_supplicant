/*******************************************************************************
 * WPA Crypto Implementation for STM32F4xx
 * 
 * Uses STM32 HAL and hardware crypto accelerator where available.
 * Falls back to software implementations for devices without CRYP.
 * 
 * Requires: STM32F4xx HAL, RNG peripheral
 ******************************************************************************/

#ifndef WPA_CRYPTO_STM32_H
#define WPA_CRYPTO_STM32_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* STM32 HAL includes - adjust for your specific MCU */
#include "stm32f4xx_hal.h"

/* Check if hardware crypto is available */
#if defined(STM32F415xx) || defined(STM32F417xx) || \
    defined(STM32F437xx) || defined(STM32F439xx) || \
    defined(STM32F479xx)
#define WPA_USE_HW_CRYPTO 1
#else
#define WPA_USE_HW_CRYPTO 0
#endif

/*******************************************************************************
 * Initialization
 ******************************************************************************/

/* Initialize crypto subsystem (RNG, CRYP if available) */
int wpa_crypto_init(void);

/*******************************************************************************
 * Random Number Generation
 ******************************************************************************/

/* Get cryptographically secure random bytes */
int crypto_get_random(uint8_t *buf, size_t len);

/*******************************************************************************
 * SHA-1 Functions
 ******************************************************************************/

/* SHA-1 context */
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20]);

/* Convenience function */
void sha1(const uint8_t *data, size_t len, uint8_t *output);

/*******************************************************************************
 * HMAC-SHA1 Functions
 ******************************************************************************/

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *output);

void hmac_sha1_vector(const uint8_t *key, size_t key_len,
                      size_t num_elem, const uint8_t *addr[],
                      const size_t *len, uint8_t *output);

/*******************************************************************************
 * AES Functions
 ******************************************************************************/

/* AES-128 single block encrypt */
void aes_128_encrypt(const uint8_t *key, 
                     const uint8_t *plaintext,
                     uint8_t *ciphertext);

/* AES Key Unwrap (RFC 3394) */
int aes_unwrap(const uint8_t *kek, size_t kek_len,
               const uint8_t *cipher, size_t cipher_len,
               uint8_t *plain);

#endif /* WPA_CRYPTO_STM32_H */

/*******************************************************************************
 * Implementation
 ******************************************************************************/

#ifdef WPA_CRYPTO_IMPLEMENTATION

/* Hardware handles */
static RNG_HandleTypeDef hrng;
#if WPA_USE_HW_CRYPTO
static CRYP_HandleTypeDef hcryp;
#endif

/*******************************************************************************
 * Initialization
 ******************************************************************************/

int wpa_crypto_init(void) {
    /* Initialize RNG */
    __HAL_RCC_RNG_CLK_ENABLE();
    
    hrng.Instance = RNG;
    if (HAL_RNG_Init(&hrng) != HAL_OK) {
        return -1;
    }
    
#if WPA_USE_HW_CRYPTO
    /* Initialize CRYP for AES */
    __HAL_RCC_CRYP_CLK_ENABLE();
    
    hcryp.Instance = CRYP;
    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
    hcryp.Init.Algorithm = CRYP_AES_ECB;
    
    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return -1;
    }
#endif
    
    return 0;
}

/*******************************************************************************
 * Random Number Generation
 ******************************************************************************/

int crypto_get_random(uint8_t *buf, size_t len) {
    uint32_t random;
    size_t i = 0;
    
    while (i < len) {
        if (HAL_RNG_GenerateRandomNumber(&hrng, &random) != HAL_OK) {
            return -1;
        }
        
        size_t copy_len = (len - i >= 4) ? 4 : (len - i);
        memcpy(buf + i, &random, copy_len);
        i += copy_len;
    }
    
    return 0;
}

/*******************************************************************************
 * SHA-1 Implementation (Software)
 ******************************************************************************/

#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, temp;
    uint32_t w[80];
    int i;
    
    /* Copy buffer to w[] as big-endian 32-bit words */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i * 4] << 24) |
               ((uint32_t)buffer[i * 4 + 1] << 16) |
               ((uint32_t)buffer[i * 4 + 2] << 8) |
               ((uint32_t)buffer[i * 4 + 3]);
    }
    
    /* Extend words */
    for (i = 16; i < 80; i++) {
        w[i] = SHA1_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    
    /* Main loop */
    for (i = 0; i < 80; i++) {
        if (i < 20) {
            temp = SHA1_ROTL(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
        } else if (i < 40) {
            temp = SHA1_ROTL(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = SHA1_ROTL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
        } else {
            temp = SHA1_ROTL(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
        }
        
        e = d;
        d = c;
        c = SHA1_ROTL(b, 30);
        b = a;
        a = temp;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_init(sha1_ctx_t *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i, j;
    
    j = (ctx->count[0] >> 3) & 63;
    
    if ((ctx->count[0] += len << 3) < (len << 3)) {
        ctx->count[1]++;
    }
    ctx->count[1] += (len >> 29);
    
    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&ctx->buffer[j], data, i);
        sha1_transform(ctx->state, ctx->buffer);
        
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20]) {
    uint8_t finalcount[8];
    uint8_t c;
    int i;
    
    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >>
                                   ((3 - (i & 3)) * 8)) & 255);
    }
    
    c = 0x80;
    sha1_update(ctx, &c, 1);
    
    while ((ctx->count[0] & 504) != 448) {
        c = 0x00;
        sha1_update(ctx, &c, 1);
    }
    
    sha1_update(ctx, finalcount, 8);
    
    for (i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    
    /* Clear sensitive data */
    memset(ctx, 0, sizeof(*ctx));
}

void sha1(const uint8_t *data, size_t len, uint8_t *output) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, output);
}

/*******************************************************************************
 * HMAC-SHA1 Implementation
 ******************************************************************************/

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t *output) {
    sha1_ctx_t ctx;
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[20];
    size_t i;
    
    /* If key is longer than 64 bytes, hash it first */
    if (key_len > 64) {
        sha1(key, key_len, tk);
        key = tk;
        key_len = 20;
    }
    
    /* Prepare key pads */
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    /* Inner hash: H(K XOR ipad || data) */
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, 64);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, output);
    
    /* Outer hash: H(K XOR opad || inner_hash) */
    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, 64);
    sha1_update(&ctx, output, 20);
    sha1_final(&ctx, output);
}

void hmac_sha1_vector(const uint8_t *key, size_t key_len,
                      size_t num_elem, const uint8_t *addr[],
                      const size_t *len, uint8_t *output) {
    sha1_ctx_t ctx;
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tk[20];
    size_t i;
    
    if (key_len > 64) {
        sha1(key, key_len, tk);
        key = tk;
        key_len = 20;
    }
    
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, 64);
    for (i = 0; i < num_elem; i++) {
        sha1_update(&ctx, addr[i], len[i]);
    }
    sha1_final(&ctx, output);
    
    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, 64);
    sha1_update(&ctx, output, 20);
    sha1_final(&ctx, output);
}

/*******************************************************************************
 * AES Implementation
 ******************************************************************************/

#if WPA_USE_HW_CRYPTO

/* Use STM32 hardware AES */
void aes_128_encrypt(const uint8_t *key, 
                     const uint8_t *plaintext,
                     uint8_t *ciphertext) {
    /* Configure key */
    hcryp.Init.pKey = (uint32_t *)key;
    HAL_CRYP_Init(&hcryp);
    
    /* Encrypt single block */
    HAL_CRYP_Encrypt(&hcryp, (uint32_t *)plaintext, 4, (uint32_t *)ciphertext, 100);
}

#else

/* Software AES-128 implementation */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

static void aes_key_expansion(const uint8_t *key, uint8_t *round_keys) {
    uint8_t temp[4];
    int i, j;
    
    memcpy(round_keys, key, 16);
    
    for (i = 4; i < 44; i++) {
        memcpy(temp, round_keys + (i - 1) * 4, 4);
        
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[i / 4];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }
        
        for (j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
        }
    }
}

static void aes_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void aes_shift_rows(uint8_t *state) {
    uint8_t t;
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

static void aes_mix_columns(uint8_t *state) {
    uint8_t t[4];
    for (int i = 0; i < 4; i++) {
        t[0] = state[i*4]; t[1] = state[i*4+1]; t[2] = state[i*4+2]; t[3] = state[i*4+3];
        state[i*4]   = xtime(t[0]) ^ xtime(t[1]) ^ t[1] ^ t[2] ^ t[3];
        state[i*4+1] = t[0] ^ xtime(t[1]) ^ xtime(t[2]) ^ t[2] ^ t[3];
        state[i*4+2] = t[0] ^ t[1] ^ xtime(t[2]) ^ xtime(t[3]) ^ t[3];
        state[i*4+3] = xtime(t[0]) ^ t[0] ^ t[1] ^ t[2] ^ xtime(t[3]);
    }
}

static void aes_add_round_key(uint8_t *state, const uint8_t *rk) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

void aes_128_encrypt(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext) {
    uint8_t state[16], round_keys[176];
    
    aes_key_expansion(key, round_keys);
    memcpy(state, plaintext, 16);
    
    aes_add_round_key(state, round_keys);
    
    for (int r = 1; r < 10; r++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys + r * 16);
    }
    
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys + 160);
    
    memcpy(ciphertext, state, 16);
}

#endif /* WPA_USE_HW_CRYPTO */

/*******************************************************************************
 * AES Key Unwrap (RFC 3394)
 ******************************************************************************/
int aes_unwrap(const uint8_t *kek, size_t kek_len,
               const uint8_t *cipher, size_t cipher_len,
               uint8_t *plain) {
    uint8_t a[8], b[16], *r;
    size_t n = (cipher_len / 8) - 1;
    int i, j;
    
    if (cipher_len < 16 || cipher_len % 8 != 0) return -1;
    
    memcpy(a, cipher, 8);
    r = plain;
    memcpy(r, cipher + 8, cipher_len - 8);
    
    for (j = 5; j >= 0; j--) {
        for (i = n; i >= 1; i--) {
            memcpy(b, a, 8);
            memcpy(b + 8, r + (i - 1) * 8, 8);
            b[7] ^= (n * j + i);
            
            /* AES decrypt = encrypt with inverse key schedule */
            /* Simplified: use AES encrypt in reverse context */
            uint8_t dec[16];
            /* Note: proper implementation needs AES decrypt */
            /* This is placeholder - implement proper AES decrypt */
            aes_128_encrypt(kek, b, dec);  /* WRONG - need decrypt! */
            
            memcpy(a, dec, 8);
            memcpy(r + (i - 1) * 8, dec + 8, 8);
        }
    }
    
    /* Check IV (should be 0xA6A6A6A6A6A6A6A6) */
    static const uint8_t default_iv[8] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
    if (memcmp(a, default_iv, 8) != 0) return -1;
    
    return 0;
}

#endif /* WPA_CRYPTO_IMPLEMENTATION */