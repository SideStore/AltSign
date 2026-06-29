//
//  native_bridge_corecrypto.cpp
//  AltSign
//

#include "native_bridge_corecrypto.h"

#include <stdlib.h>
#include <string.h>

#define CORECRYPTO_USE_TRANSPARENT_UNION 1
#define CC_INTERNAL_SDK 1
#define CC_USE_L4 0

extern "C" {
    
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsrp.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode.h>



// ============================================================
// MARK: - SRP
// ============================================================

const void* native_bridge_ccsrp_gp_rfc5054_2048(void)
{
    return ccsrp_gp_rfc5054_2048();
}

const void* native_bridge_ccsha256_di(void)
{
    return ccsha256_di();
}

native_bridge_ccsrp_ctx native_bridge_ccsrp_client_new(void)
{
    ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();
    const struct ccdigest_info *di = ccsha256_di();

    size_t size = 4096; // large enough workspace
    ccsrp_ctx_t ctx = (ccsrp_ctx_t)malloc(size);

    if (!ctx) return nullptr;

    ccsrp_ctx_init(ctx, di, gp);
    ccsrp_client_set_noUsernameInX(ctx, true);
    return ctx;
}

void native_bridge_ccsrp_client_free(native_bridge_ccsrp_ctx ctx)
{
    if (ctx) free(ctx);
}

size_t native_bridge_ccsrp_exchange_size(native_bridge_ccsrp_ctx ctx)
{
    return ccsrp_exchange_size((ccsrp_ctx_t)ctx);
}

int native_bridge_ccsrp_client_start_authentication(
    native_bridge_ccsrp_ctx ctx,
    void *A_bytes,
    void *rng)
{
    struct ccrng_state *rng_state = (struct ccrng_state*)rng;
    if (!rng_state) {
        int err = 0;
        rng_state = ccrng(&err);
    }
    return ccsrp_client_start_authentication(
        (ccsrp_ctx_t)ctx,
        rng_state,
        A_bytes
    );
}

int native_bridge_ccsrp_client_process_challenge(
    native_bridge_ccsrp_ctx ctx,
    const void *salt,
    size_t salt_len,
    const void *B,
    size_t B_len,
    const char *username,
    const void *password,
    size_t password_len,
    void *M_bytes
)
{
    return ccsrp_client_process_challenge(
        (ccsrp_ctx_t)ctx,
        username,
        password_len,
        password,
        salt_len,
        salt,
        B,
        M_bytes
    );
}

int native_bridge_ccsrp_client_verify_session(
    native_bridge_ccsrp_ctx ctx,
    const void *M2
)
{
    return ccsrp_client_verify_session(
        (ccsrp_ctx_t)ctx,
        (const uint8_t*)M2
    );
}

const void* native_bridge_ccsrp_get_session_key(native_bridge_ccsrp_ctx ctx)
{
    size_t len = 0;
    return ccsrp_get_session_key((ccsrp_ctx_t)ctx, &len);
}

size_t native_bridge_ccsrp_get_session_key_length(native_bridge_ccsrp_ctx ctx)
{
    return ccsrp_get_session_key_length((ccsrp_ctx_t)ctx);
}


// ============================================================
// MARK: - HMAC
// ============================================================

size_t native_bridge_cchmac_di_size(const void *di)
{
    const struct ccdigest_info *d =
        (const struct ccdigest_info*)di;

    return cchmac_ctx_size(d->state_size, d->block_size);
}

native_bridge_cchmac_ctx native_bridge_cchmac_create(const void *di)
{
    const struct ccdigest_info *d =
        (const struct ccdigest_info*)di;

    size_t size =
        cchmac_ctx_size(d->state_size, d->block_size);

    return malloc(size);
}

void native_bridge_cchmac_free(native_bridge_cchmac_ctx ctx)
{
    free(ctx);
}

void native_bridge_cchmac_init(
    native_bridge_cchmac_ctx ctx,
    const void *di,
    const void *key,
    size_t key_len
)
{
    cchmac_init(
        (const struct ccdigest_info*)di,
        (cchmac_ctx_t)ctx,
        key_len,
        key
    );
}

void native_bridge_cchmac_update(
    native_bridge_cchmac_ctx ctx,
    const void *di,
    const void *data,
    size_t len
)
{
    cchmac_update(
        (const struct ccdigest_info*)di,
        (cchmac_ctx_t)ctx,
        len,
        data
    );
}

void native_bridge_cchmac_final(
    native_bridge_cchmac_ctx ctx,
    const void *di,
    void *out
)
{
    cchmac_final(
        (const struct ccdigest_info*)di,
        (cchmac_ctx_t)ctx,
        (unsigned char*)out
    );
}


// ============================================================
// MARK: - PBKDF2
// ============================================================

int native_bridge_ccpbkdf2_hmac(
    const void *di,
    const char *password,
    size_t passwordLen,
    const void *salt,
    size_t saltLen,
    unsigned rounds,
    void *derivedKey,
    size_t derivedKeyLen
)
{
    return ccpbkdf2_hmac(
        (const struct ccdigest_info*)di,
        passwordLen,
        password,
        saltLen,
        salt,
        rounds,
        derivedKeyLen,
        derivedKey
    );
}


// ============================================================
// MARK: - SHA256 Digest
// ============================================================

int native_bridge_ccdigest_sha256(
    const void *data,
    size_t len,
    void *out
)
{
    const struct ccdigest_info *di = ccsha256_di();
    ccdigest(di, len, data, out);
    return 0;
}


// ============================================================
// MARK: - AES CBC PKCS7
// ============================================================
int native_bridge_aes_cbc_pkcs7_decrypt(
    const void *key,
    size_t key_len,
    const void *iv_bytes,
    const void *input,
    size_t input_len,
    void *output,
    size_t *output_len
)
{
    const struct ccmode_cbc *mode = ccaes_cbc_decrypt_mode();

    /* allocate CBC context */
    size_t ctx_size = cccbc_context_size(mode);
    cccbc_ctx *ctx = (cccbc_ctx *)malloc(ctx_size);
    if (!ctx) return -1;

    /* init key */
    mode->init(mode, ctx, key_len, key);

    /* IV object (NOT raw bytes) */
    cccbc_iv iv;
    memcpy(&iv, iv_bytes, mode->block_size);

    /* decrypt */
    size_t written =
        ccpad_pkcs7_decrypt(
            mode,
            ctx,
            &iv,
            input_len,
            input,
            output
        );

    free(ctx);

    if (written == 0)
        return -1;

    *output_len = written;
    return 0;
}


// ============================================================
// MARK: - AES GCM
// ============================================================
int native_bridge_aes_gcm_decrypt(
    const void *key,
    size_t key_len,
    const void *nonce,
    size_t nonce_len,
    const void *aad,
    size_t aad_len,
    const void *ciphertext,
    size_t ciphertext_len,
    const void *tag,
    size_t tag_len,
    void *plaintext
)
{
    const struct ccmode_gcm *mode = ccaes_gcm_decrypt_mode();

    size_t ctx_size = ccgcm_context_size(mode);
    ccgcm_ctx *ctx = (ccgcm_ctx *)malloc(ctx_size);
    if (!ctx) return -1;

    /* init */
    ccgcm_init(mode, ctx, key_len, key);

    /* IV */
    ccgcm_set_iv(mode, ctx, nonce_len, (void *)nonce);

    /* AAD */
    if (aad && aad_len > 0) {
        ccgcm_aad(mode, ctx, aad_len, (void *)aad);
    }

    /* decrypt */
    ccgcm_update(
        mode,
        ctx,
        ciphertext_len,
        ciphertext,
        plaintext
    );

    /* verify tag using a local mutable buffer to avoid writing to read-only memory */
    void *temp_tag = malloc(tag_len);
    if (!temp_tag) {
        free(ctx);
        return -1;
    }
    memcpy(temp_tag, tag, tag_len);

    int rc = ccgcm_finalize(
        mode,
        ctx,
        tag_len,
        temp_tag
    );

    free(temp_tag);
    free(ctx);
    return rc;
}

} // extern "C"
