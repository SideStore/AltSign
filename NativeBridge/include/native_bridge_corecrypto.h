//
//  native_bridge_corecrypto.h
//  AltSign
//
//  Created by Magesh K on 25/02/26.
//

#pragma once
#include "native_bridge_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* native_bridge_ccsrp_ctx;
typedef void* native_bridge_cchmac_ctx;

/* SRP */

const void* native_bridge_ccsrp_gp_rfc5054_2048(void);
const void* native_bridge_ccsha256_di(void);

native_bridge_ccsrp_ctx native_bridge_ccsrp_client_new(void);
void native_bridge_ccsrp_client_free(native_bridge_ccsrp_ctx ctx);

size_t native_bridge_ccsrp_exchange_size(native_bridge_ccsrp_ctx ctx);

int native_bridge_ccsrp_client_start_authentication(
    native_bridge_ccsrp_ctx ctx,
    void *A_bytes,
    void *rng
);

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
);

int native_bridge_ccsrp_client_verify_session(
    native_bridge_ccsrp_ctx ctx,
    const void *M2
);

const void* native_bridge_ccsrp_get_session_key(native_bridge_ccsrp_ctx ctx);
size_t native_bridge_ccsrp_get_session_key_length(native_bridge_ccsrp_ctx ctx);

/* HMAC */

size_t native_bridge_cchmac_di_size(const void *di);

native_bridge_cchmac_ctx native_bridge_cchmac_create(const void *di);
void native_bridge_cchmac_free(native_bridge_cchmac_ctx ctx);

void native_bridge_cchmac_init(
    native_bridge_cchmac_ctx ctx,
    const void *di,
    const void *key,
    size_t key_len
);

void native_bridge_cchmac_update(
    native_bridge_cchmac_ctx ctx,
    const void *di,
    const void *data,
    size_t len
);

void native_bridge_cchmac_final(
    native_bridge_cchmac_ctx ctx,
    const void *di,
    void *out
);

/* PBKDF2 */

int native_bridge_ccpbkdf2_hmac(
    const void *di,
    const char *password,
    size_t passwordLen,
    const void *salt,
    size_t saltLen,
    unsigned rounds,
    void *derivedKey,
    size_t derivedKeyLen
);

/* Digest */

int native_bridge_ccdigest_sha256(
    const void *data,
    size_t len,
    void *out
);

/* AES CBC (PKCS7) */

int native_bridge_aes_cbc_pkcs7_decrypt(
    const void *key,
    size_t key_len,
    const void *iv,
    const void *input,
    size_t input_len,
    void *output,
    size_t *output_len
);

/* AES GCM */

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
);

#ifdef __cplusplus
}
#endif
