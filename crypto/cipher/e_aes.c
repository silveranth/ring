/* ====================================================================
 * Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/cipher.h>
#include <openssl/cpu.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/modes.h>
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../modes/internal.h"


typedef struct {
  union {
    double align;
    AES_KEY ks;
  } ks;
  block128_f block;
  union {
    cbc128_f cbc;
    ctr128_f ctr;
  } stream;
} EVP_AES_KEY;

typedef struct {
  union {
    double align;
    AES_KEY ks;
  } ks;        /* AES key schedule to use */
  int key_set; /* Set if key initialised */
  int iv_set;  /* Set if an iv is set */
  GCM128_CONTEXT gcm;
  uint8_t *iv; /* Temporary IV store */
  int ivlen;         /* IV length */
  int taglen;
  int iv_gen;      /* It is OK to generate IVs */
  ctr128_f ctr;
} EVP_AES_GCM_CTX;

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
#define VPAES
extern unsigned int OPENSSL_ia32cap_P[];

static char vpaes_capable() {
  return (OPENSSL_ia32cap_P[1] & (1 << (41 - 32))) != 0;
}

#if defined(OPENSSL_X86_64)
#define BSAES
static char bsaes_capable() {
  return vpaes_capable();
}
#endif

#elif !defined(OPENSSL_NO_ASM) && defined(OPENSSL_ARM)
#include "../arm_arch.h"
#if __ARM_ARCH__ >= 7
#define BSAES
static char bsaes_capable() {
  return CRYPTO_is_NEON_capable();
}
#endif  /* __ARM_ARCH__ >= 7 */
#endif  /* OPENSSL_ARM */

#if defined(BSAES)
/* On platforms where BSAES gets defined (just above), then these functions are
 * provided by asm. */
void bsaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t ivec[16], int enc);
void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);
#else
static char bsaes_capable() {
  return 0;
}

/* On other platforms, bsaes_capable() will always return false and so the
 * following will never be called. */
void bsaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t ivec[16], int enc) {
  abort();
}

void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]) {
  abort();
}
#endif

#if defined(VPAES)
/* On platforms where VPAES gets defined (just above), then these functions are
 * provided by asm. */
int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
int vpaes_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);

void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void vpaes_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

void vpaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t *ivec, int enc);
#else
static char vpaes_capable() {
  return 0;
}

/* On other platforms, vpaes_capable() will always return false and so the
 * following will never be called. */
int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key) {
  abort();
}
int vpaes_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key) {
  abort();
}
void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  abort();
}
void vpaes_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  abort();
}
void vpaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t *ivec, int enc) {
  abort();
}
#endif

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
int aesni_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
int aesni_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);

void aesni_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aesni_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

void aesni_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, int enc);
void aesni_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t *ivec, int enc);

void aesni_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t blocks,
                                const void *key, const uint8_t *ivec);

#if defined(OPENSSL_X86_64)
size_t aesni_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const void *key, uint8_t ivec[16], uint64_t *Xi);
#define AES_gcm_encrypt aesni_gcm_encrypt
size_t aesni_gcm_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                         const void *key, uint8_t ivec[16], uint64_t *Xi);
#define AES_gcm_decrypt aesni_gcm_decrypt
void gcm_ghash_avx(uint64_t Xi[2], const u128 Htable[16], const uint8_t *in,
                   size_t len);
#define AES_GCM_ASM(gctx) \
  (gctx->ctr == aesni_ctr32_encrypt_blocks && gctx->gcm.ghash == gcm_ghash_avx)
#endif  /* OPENSSL_X86_64 */

#else

/* On other platforms, aesni_capable() will always return false and so the
 * following will never be called. */
void aesni_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  abort();
}
int aesni_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key) {
  abort();
}
void aesni_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t blocks,
                                const void *key, const uint8_t *ivec) {
  abort();
}

#endif

static int aes_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc) {
  int ret, mode;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    if (bsaes_capable() && mode == EVP_CIPH_CBC_MODE) {
      ret = AES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)AES_decrypt;
      dat->stream.cbc = (cbc128_f)bsaes_cbc_encrypt;
    } else if (vpaes_capable()) {
      ret = vpaes_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)vpaes_decrypt;
      dat->stream.cbc =
          mode == EVP_CIPH_CBC_MODE ? (cbc128_f)vpaes_cbc_encrypt : NULL;
    } else {
      ret = AES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)AES_decrypt;
      dat->stream.cbc =
          mode == EVP_CIPH_CBC_MODE ? (cbc128_f)AES_cbc_encrypt : NULL;
    }
  } else if (bsaes_capable() && mode == EVP_CIPH_CTR_MODE) {
    ret = AES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)AES_encrypt;
    dat->stream.ctr = (ctr128_f)bsaes_ctr32_encrypt_blocks;
  } else if (vpaes_capable()) {
    ret = vpaes_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)vpaes_encrypt;
    dat->stream.cbc =
        mode == EVP_CIPH_CBC_MODE ? (cbc128_f)vpaes_cbc_encrypt : NULL;
  } else {
    ret = AES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)AES_encrypt;
    dat->stream.cbc =
        mode == EVP_CIPH_CBC_MODE ? (cbc128_f)AES_cbc_encrypt : NULL;
  }

  if (ret < 0) {
    OPENSSL_PUT_ERROR(CIPHER, aes_init_key, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

static int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  if (dat->stream.cbc) {
    (*dat->stream.cbc)(in, out, len, &dat->ks, ctx->iv, ctx->encrypt);
  } else if (ctx->encrypt) {
    CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  } else {
    CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  }

  return 1;
}

static int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  size_t bl = ctx->cipher->block_size;
  size_t i;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  if (len < bl) {
    return 1;
  }

  for (i = 0, len -= bl; i <= len; i += bl) {
    (*dat->block)(in + i, out + i, &dat->ks);
  }

  return 1;
}

static int aes_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len) {
  unsigned int num = ctx->num;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  if (dat->stream.ctr) {
    CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num,
                                dat->stream.ctr);
  } else {
    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num,
                          dat->block);
  }
  ctx->num = (size_t)num;
  return 1;
}

static ctr128_f aes_gcm_set_key(AES_KEY *aes_key, GCM128_CONTEXT *gcm_ctx,
                                const uint8_t *key, size_t key_len) {
  if (bsaes_capable()) {
    AES_set_encrypt_key(key, key_len * 8, aes_key);
    CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)AES_encrypt);
    return (ctr128_f)bsaes_ctr32_encrypt_blocks;
  }

  if (vpaes_capable()) {
    vpaes_set_encrypt_key(key, key_len * 8, aes_key);
    CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)vpaes_encrypt);
    return NULL;
  }

  AES_set_encrypt_key(key, key_len * 8, aes_key);
  CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)AES_encrypt);
  return NULL;
}

static int aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                            const uint8_t *iv, int enc) {
  EVP_AES_GCM_CTX *gctx = ctx->cipher_data;
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    gctx->ctr = aes_gcm_set_key(&gctx->ks.ks, &gctx->gcm, key, ctx->key_len);
    /* If we have an iv can set it directly, otherwise use saved IV. */
    if (iv == NULL && gctx->iv_set) {
      iv = gctx->iv;
    }
    if (iv) {
      CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
      gctx->iv_set = 1;
    }
    gctx->key_set = 1;
  } else {
    /* If key set use IV, otherwise copy */
    if (gctx->key_set) {
      CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
    } else {
      memcpy(gctx->iv, iv, gctx->ivlen);
    }
    gctx->iv_set = 1;
    gctx->iv_gen = 0;
  }
  return 1;
}

static int aes_gcm_cleanup(EVP_CIPHER_CTX *c) {
  EVP_AES_GCM_CTX *gctx = c->cipher_data;
  OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
  if (gctx->iv != c->iv) {
    OPENSSL_free(gctx->iv);
  }
  return 1;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(uint8_t *counter) {
  int n = 8;
  uint8_t c;

  do {
    --n;
    c = counter[n];
    ++c;
    counter[n] = c;
    if (c) {
      return;
    }
  } while (n);
}

static int aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr) {
  EVP_AES_GCM_CTX *gctx = c->cipher_data;
  switch (type) {
    case EVP_CTRL_INIT:
      gctx->key_set = 0;
      gctx->iv_set = 0;
      gctx->ivlen = c->cipher->iv_len;
      gctx->iv = c->iv;
      gctx->taglen = -1;
      gctx->iv_gen = 0;
      return 1;

    case EVP_CTRL_GCM_SET_IVLEN:
      if (arg <= 0) {
        return 0;
      }

      /* Allocate memory for IV if needed */
      if (arg > EVP_MAX_IV_LENGTH && arg > gctx->ivlen) {
        if (gctx->iv != c->iv) {
          OPENSSL_free(gctx->iv);
        }
        gctx->iv = OPENSSL_malloc(arg);
        if (!gctx->iv) {
          return 0;
        }
      }
      gctx->ivlen = arg;
      return 1;

    case EVP_CTRL_GCM_SET_TAG:
      if (arg <= 0 || arg > 16 || c->encrypt) {
        return 0;
      }
      memcpy(c->buf, ptr, arg);
      gctx->taglen = arg;
      return 1;

    case EVP_CTRL_GCM_GET_TAG:
      if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0) {
        return 0;
      }
      memcpy(ptr, c->buf, arg);
      return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
      /* Special case: -1 length restores whole IV */
      if (arg == -1) {
        memcpy(gctx->iv, ptr, gctx->ivlen);
        gctx->iv_gen = 1;
        return 1;
      }
      /* Fixed field must be at least 4 bytes and invocation field
       * at least 8. */
      if (arg < 4 || (gctx->ivlen - arg) < 8) {
        return 0;
      }
      if (arg) {
        memcpy(gctx->iv, ptr, arg);
      }
      if (c->encrypt &&
          RAND_pseudo_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0) {
        return 0;
      }
      gctx->iv_gen = 1;
      return 1;

    case EVP_CTRL_GCM_IV_GEN:
      if (gctx->iv_gen == 0 || gctx->key_set == 0) {
        return 0;
      }
      CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
      if (arg <= 0 || arg > gctx->ivlen) {
        arg = gctx->ivlen;
      }
      memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
      /* Invocation field will be at least 8 bytes in size and
       * so no need to check wrap around or increment more than
       * last 8 bytes. */
      ctr64_inc(gctx->iv + gctx->ivlen - 8);
      gctx->iv_set = 1;
      return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
      if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt) {
        return 0;
      }
      memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
      CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
      gctx->iv_set = 1;
      return 1;

    default:
      return -1;
  }
}

static int aes_gcm_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t len) {
  EVP_AES_GCM_CTX *gctx = ctx->cipher_data;

  /* If not set up, return error */
  if (!gctx->key_set) {
    return -1;
  }
  if (!gctx->iv_set) {
    return -1;
  }

  if (in) {
    if (out == NULL) {
      if (!CRYPTO_gcm128_aad(&gctx->gcm, in, len)) {
        return -1;
      }
    } else if (ctx->encrypt) {
      if (gctx->ctr) {
        size_t bulk = 0;
#if defined(AES_GCM_ASM)
        if (len >= 32 && AES_GCM_ASM(gctx)) {
          size_t res = (16 - gctx->gcm.mres) % 16;

          if (!CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, res)) {
            return -1;
          }

          bulk = AES_gcm_encrypt(in + res, out + res, len - res, gctx->gcm.key,
                                 gctx->gcm.Yi.c, gctx->gcm.Xi.u);
          gctx->gcm.len.u[1] += bulk;
          bulk += res;
        }
#endif
        if (!CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm, in + bulk, out + bulk,
                                        len - bulk, gctx->ctr)) {
          return -1;
        }
      } else {
        size_t bulk = 0;
        if (!CRYPTO_gcm128_encrypt(&gctx->gcm, in + bulk, out + bulk,
                                  len - bulk)) {
          return -1;
        }
      }
    } else {
      if (gctx->ctr) {
        size_t bulk = 0;
#if defined(AES_GCM_ASM)
        if (len >= 16 && AES_GCM_ASM(gctx)) {
          size_t res = (16 - gctx->gcm.mres) % 16;

          if (!CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, res)) {
            return -1;
          }

          bulk = AES_gcm_decrypt(in + res, out + res, len - res, gctx->gcm.key,
                                 gctx->gcm.Yi.c, gctx->gcm.Xi.u);
          gctx->gcm.len.u[1] += bulk;
          bulk += res;
        }
#endif
        if (!CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm, in + bulk, out + bulk,
                                        len - bulk, gctx->ctr)) {
          return -1;
        }
      } else {
        size_t bulk = 0;
        if (!CRYPTO_gcm128_decrypt(&gctx->gcm, in + bulk, out + bulk,
                                  len - bulk)) {
          return -1;
        }
      }
    }
    return len;
  } else {
    if (!ctx->encrypt) {
      if (gctx->taglen < 0 ||
          !CRYPTO_gcm128_finish(&gctx->gcm, ctx->buf, gctx->taglen) != 0) {
        return -1;
      }
      gctx->iv_set = 0;
      return 0;
    }
    CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
    gctx->taglen = 16;
    /* Don't reuse the IV */
    gctx->iv_set = 0;
    return 0;
  }
}

static const EVP_CIPHER aes_128_cbc = {
    NID_aes_128_cbc,     16 /* block_size */, 16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aes_init_key,        aes_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_128_ctr = {
    NID_aes_128_ctr,     1 /* block_size */,  16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aes_init_key,        aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_128_ecb = {
    NID_aes_128_ecb,     16 /* block_size */, 16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_ECB_MODE,
    NULL /* app_data */, aes_init_key,        aes_ecb_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_128_gcm = {
    NID_aes_128_gcm, 1 /* block_size */, 16 /* key_size */, 12 /* iv_len */,
    sizeof(EVP_AES_GCM_CTX),
    EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |
        EVP_CIPH_FLAG_AEAD_CIPHER,
    NULL /* app_data */, aes_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup,
    aes_gcm_ctrl};


static const EVP_CIPHER aes_256_cbc = {
    NID_aes_128_cbc,     16 /* block_size */, 32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aes_init_key,        aes_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_256_ctr = {
    NID_aes_128_ctr,     1 /* block_size */,  32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aes_init_key,        aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_256_ecb = {
    NID_aes_128_ecb,     16 /* block_size */, 32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_ECB_MODE,
    NULL /* app_data */, aes_init_key,        aes_ecb_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_256_gcm = {
    NID_aes_128_gcm, 1 /* block_size */, 32 /* key_size */, 12 /* iv_len */,
    sizeof(EVP_AES_GCM_CTX),
    EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |
        EVP_CIPH_FLAG_AEAD_CIPHER,
    NULL /* app_data */, aes_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup,
    aes_gcm_ctrl};

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))

/* AES-NI section. */

static char aesni_capable() {
  return (OPENSSL_ia32cap_P[1] & (1 << (57 - 32))) != 0;
}

static int aesni_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                          const uint8_t *iv, int enc) {
  int ret, mode;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    ret = aesni_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
    dat->block = (block128_f)aesni_decrypt;
    dat->stream.cbc =
        mode == EVP_CIPH_CBC_MODE ? (cbc128_f)aesni_cbc_encrypt : NULL;
  } else {
    ret = aesni_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
    dat->block = (block128_f)aesni_encrypt;
    if (mode == EVP_CIPH_CBC_MODE) {
      dat->stream.cbc = (cbc128_f)aesni_cbc_encrypt;
    } else if (mode == EVP_CIPH_CTR_MODE) {
      dat->stream.ctr = (ctr128_f)aesni_ctr32_encrypt_blocks;
    } else {
      dat->stream.cbc = NULL;
    }
  }

  if (ret < 0) {
    OPENSSL_PUT_ERROR(CIPHER, aesni_init_key, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

static int aesni_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                            const uint8_t *in, size_t len) {
  aesni_cbc_encrypt(in, out, len, ctx->cipher_data, ctx->iv, ctx->encrypt);

  return 1;
}

static int aesni_ecb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                            const uint8_t *in, size_t len) {
  size_t bl = ctx->cipher->block_size;

  if (len < bl) {
    return 1;
  }

  aesni_ecb_encrypt(in, out, len, ctx->cipher_data, ctx->encrypt);

  return 1;
}

static int aesni_gcm_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                              const uint8_t *iv, int enc) {
  EVP_AES_GCM_CTX *gctx = ctx->cipher_data;
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    aesni_set_encrypt_key(key, ctx->key_len * 8, &gctx->ks.ks);
    CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks, (block128_f)aesni_encrypt);
    gctx->ctr = (ctr128_f)aesni_ctr32_encrypt_blocks;
    /* If we have an iv can set it directly, otherwise use
     * saved IV. */
    if (iv == NULL && gctx->iv_set) {
      iv = gctx->iv;
    }
    if (iv) {
      CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
      gctx->iv_set = 1;
    }
    gctx->key_set = 1;
  } else {
    /* If key set use IV, otherwise copy */
    if (gctx->key_set) {
      CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
    } else {
      memcpy(gctx->iv, iv, gctx->ivlen);
    }
    gctx->iv_set = 1;
    gctx->iv_gen = 0;
  }
  return 1;
}

static const EVP_CIPHER aesni_128_cbc = {
    NID_aes_128_cbc,     16 /* block_size */, 16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aesni_init_key,      aesni_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_128_ctr = {
    NID_aes_128_ctr,     1 /* block_size */,  16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aesni_init_key,      aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_128_ecb = {
    NID_aes_128_ecb,     16 /* block_size */, 16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_ECB_MODE,
    NULL /* app_data */, aesni_init_key,      aesni_ecb_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_128_gcm = {
    NID_aes_128_gcm, 1 /* block_size */, 16 /* key_size */, 12 /* iv_len */,
    sizeof(EVP_AES_GCM_CTX),
    EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |
        EVP_CIPH_FLAG_AEAD_CIPHER,
    NULL /* app_data */, aesni_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup,
    aes_gcm_ctrl};


static const EVP_CIPHER aesni_256_cbc = {
    NID_aes_128_cbc,     16 /* block_size */, 32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aesni_init_key,      aesni_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_256_ctr = {
    NID_aes_128_ctr,     1 /* block_size */,  32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aesni_init_key,      aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_256_ecb = {
    NID_aes_128_ecb,     16 /* block_size */, 32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_ECB_MODE,
    NULL /* app_data */, aesni_init_key,      aesni_ecb_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_256_gcm = {
    NID_aes_256_gcm, 1 /* block_size */, 32 /* key_size */, 12 /* iv_len */,
    sizeof(EVP_AES_GCM_CTX),
    EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT |
        EVP_CIPH_FLAG_AEAD_CIPHER,
    NULL /* app_data */, aesni_gcm_init_key, aes_gcm_cipher, aes_gcm_cleanup,
    aes_gcm_ctrl};

#define EVP_CIPHER_FUNCTION(keybits, mode)             \
  const EVP_CIPHER *EVP_aes_##keybits##_##mode(void) { \
    if (aesni_capable()) {                             \
      return &aesni_##keybits##_##mode;                \
    } else {                                           \
      return &aes_##keybits##_##mode;                  \
    }                                                  \
  }

#else  /* ^^^  OPENSSL_X86_64 || OPENSSL_X86 */

static char aesni_capable() {
  return 0;
}

#define EVP_CIPHER_FUNCTION(keybits, mode)             \
  const EVP_CIPHER *EVP_aes_##keybits##_##mode(void) { \
    return &aes_##keybits##_##mode;                    \
  }

#endif

EVP_CIPHER_FUNCTION(128, cbc)
EVP_CIPHER_FUNCTION(128, ctr)
EVP_CIPHER_FUNCTION(128, ecb)
EVP_CIPHER_FUNCTION(128, gcm)

EVP_CIPHER_FUNCTION(256, cbc)
EVP_CIPHER_FUNCTION(256, ctr)
EVP_CIPHER_FUNCTION(256, ecb)
EVP_CIPHER_FUNCTION(256, gcm)


#define EVP_AEAD_AES_GCM_TAG_LEN 16

struct aead_aes_gcm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  GCM128_CONTEXT gcm;
  ctr128_f ctr;
  uint8_t tag_len;
};

static int aead_aes_gcm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                             size_t key_len, size_t tag_len) {
  struct aead_aes_gcm_ctx *gcm_ctx;
  const size_t key_bits = key_len * 8;

  if (key_bits != 128 && key_bits != 256) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_init, CIPHER_R_BAD_KEY_LENGTH);
    return 0; /* EVP_AEAD_CTX_init should catch this. */
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = EVP_AEAD_AES_GCM_TAG_LEN;
  }

  if (tag_len > EVP_AEAD_AES_GCM_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_init, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  gcm_ctx = OPENSSL_malloc(sizeof(struct aead_aes_gcm_ctx));
  if (gcm_ctx == NULL) {
    return 0;
  }

  if (aesni_capable()) {
    aesni_set_encrypt_key(key, key_len * 8, &gcm_ctx->ks.ks);
    CRYPTO_gcm128_init(&gcm_ctx->gcm, &gcm_ctx->ks.ks,
                       (block128_f)aesni_encrypt);
    gcm_ctx->ctr = (ctr128_f)aesni_ctr32_encrypt_blocks;
  } else {
    gcm_ctx->ctr =
        aes_gcm_set_key(&gcm_ctx->ks.ks, &gcm_ctx->gcm, key, key_len);
  }
  gcm_ctx->tag_len = tag_len;
  ctx->aead_state = gcm_ctx;

  return 1;
}

static void aead_aes_gcm_cleanup(EVP_AEAD_CTX *ctx) {
  struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
  OPENSSL_cleanse(gcm_ctx, sizeof(struct aead_aes_gcm_ctx));
  OPENSSL_free(gcm_ctx);
}

static int aead_aes_gcm_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                             size_t *out_len, size_t max_out_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *in, size_t in_len,
                             const uint8_t *ad, size_t ad_len) {
  size_t bulk = 0;
  const struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
  GCM128_CONTEXT gcm;

  if (in_len + gcm_ctx->tag_len < in_len) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_seal, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + gcm_ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_seal, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
  CRYPTO_gcm128_setiv(&gcm, nonce, nonce_len);

  if (ad_len > 0 && !CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }

  if (gcm_ctx->ctr) {
    if (!CRYPTO_gcm128_encrypt_ctr32(&gcm, in + bulk, out + bulk, in_len - bulk,
                                     gcm_ctx->ctr)) {
      return 0;
    }
  } else {
    if (!CRYPTO_gcm128_encrypt(&gcm, in + bulk, out + bulk, in_len - bulk)) {
      return 0;
    }
  }

  CRYPTO_gcm128_tag(&gcm, out + in_len, gcm_ctx->tag_len);
  *out_len = in_len + gcm_ctx->tag_len;
  return 1;
}

static int aead_aes_gcm_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                             size_t *out_len, size_t max_out_len,
                             const uint8_t *nonce, size_t nonce_len,
                             const uint8_t *in, size_t in_len,
                             const uint8_t *ad, size_t ad_len) {
  size_t bulk = 0;
  const struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
  uint8_t tag[EVP_AEAD_AES_GCM_TAG_LEN];
  size_t plaintext_len;
  GCM128_CONTEXT gcm;

  if (in_len < gcm_ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_open, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  plaintext_len = in_len - gcm_ctx->tag_len;

  if (max_out_len < plaintext_len) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_open, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
  CRYPTO_gcm128_setiv(&gcm, nonce, nonce_len);

  if (!CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }

  if (gcm_ctx->ctr) {
    if (!CRYPTO_gcm128_decrypt_ctr32(&gcm, in + bulk, out + bulk,
                                     in_len - bulk - gcm_ctx->tag_len,
                                     gcm_ctx->ctr)) {
      return 0;
    }
  } else {
    if (!CRYPTO_gcm128_decrypt(&gcm, in + bulk, out + bulk,
                               in_len - bulk - gcm_ctx->tag_len)) {
      return 0;
    }
  }

  CRYPTO_gcm128_tag(&gcm, tag, gcm_ctx->tag_len);
  if (CRYPTO_memcmp(tag, in + plaintext_len, gcm_ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, aead_aes_gcm_open, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  *out_len = plaintext_len;
  return 1;
}

static const EVP_AEAD aead_aes_128_gcm = {
    16,                       /* key len */
    12,                       /* nonce len */
    EVP_AEAD_AES_GCM_TAG_LEN, /* overhead */
    EVP_AEAD_AES_GCM_TAG_LEN, /* max tag length */
    aead_aes_gcm_init,        aead_aes_gcm_cleanup,
    aead_aes_gcm_seal,        aead_aes_gcm_open,
};

static const EVP_AEAD aead_aes_256_gcm = {
    32,                       /* key len */
    12,                       /* nonce len */
    EVP_AEAD_AES_GCM_TAG_LEN, /* overhead */
    EVP_AEAD_AES_GCM_TAG_LEN, /* max tag length */
    aead_aes_gcm_init,        aead_aes_gcm_cleanup,
    aead_aes_gcm_seal,        aead_aes_gcm_open,
};

const EVP_AEAD *EVP_aead_aes_128_gcm() { return &aead_aes_128_gcm; }

const EVP_AEAD *EVP_aead_aes_256_gcm() { return &aead_aes_256_gcm; }
