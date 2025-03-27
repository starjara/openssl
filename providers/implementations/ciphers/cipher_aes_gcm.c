/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
#include "internal/deprecated.h"

/* Dispatch functions for AES GCM mode */

#include "cipher_aes_gcm.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

/* JARA: For Dom-V */
#include "domv/domv.h"
//#define LOG_E printf("[openssl-cipher_aes_gcm.c] Enter: %s\n", __func__);
#define LOG_E
/* End of JARA */

static void *aes_gcm_newctx(void *provctx, size_t keybits)
{
    PROV_AES_GCM_CTX *ctx;

    LOG_E

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
   
    if (ctx != NULL)
        ossl_gcm_initctx(provctx, &ctx->base, keybits,
                         ossl_prov_aes_hw_gcm(keybits));

   /* JARA: allocate AESkey */
    domv_create(ctx->base.vmid);
    domv_enter(ctx->base.vmid);
    ctx->ks.ks = (AES_KEY *)((u32)domv_mmap(0x90000000, 0, 4096, PROT_READ|PROT_WRITE) | (u32)ctx->base.vmid);
    domv_exit();
    /* End of JARA */
  

    return ctx;
}

static void *aes_gcm_dupctx(void *provctx)
{
    PROV_AES_GCM_CTX *ctx = provctx;
    PROV_AES_GCM_CTX *dctx = NULL;

    if (ctx == NULL)
        return NULL;

    dctx = OPENSSL_memdup(ctx, sizeof(*ctx));
    if (dctx != NULL && dctx->base.gcm.key != NULL)
        dctx->base.gcm.key = &dctx->ks.ks;

    return dctx;
}

static OSSL_FUNC_cipher_freectx_fn aes_gcm_freectx;
static void aes_gcm_freectx(void *vctx)
{
    PROV_AES_GCM_CTX *ctx = (PROV_AES_GCM_CTX *)vctx;

    /* JARA: destroy the domain */
    domv_enter(ctx->base.vmid);
    domv_munmap(0x90000000);
    domv_exit();
    domv_destroy(ctx->base.vmid);
    /* End of JARA */

    OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

/* ossl_aes128gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96);
/* ossl_aes192gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96);
/* ossl_aes256gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);
