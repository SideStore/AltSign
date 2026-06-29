// native_bridge_openssl.cpp

#include "native_bridge_openssl.h"

#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

#include <cstdlib>
#include <cstring>
#include <openssl/err.h>

static uint8_t *nb_copy_bio(BIO *bio, int32_t *len)
{
    char *data = nullptr;
    long size = BIO_get_mem_data(bio, &data);

    uint8_t *out = (uint8_t *)malloc(size);
    memcpy(out, data, size);

    *len = (int32_t)size;
    return out;
}

static X509 *read_cert(const uint8_t *bytes, int32_t len)
{
    BIO *bio = BIO_new_mem_buf(bytes, len);
    if (!bio) return nullptr;
    // Try DER format first
    X509 *cert = d2i_X509_bio(bio, nullptr);
    if (!cert) {
        // Fall back to PEM format
        (void)BIO_reset(bio);
        cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    }
    BIO_free(bio);
    return cert;
}

static EVP_PKEY *read_private_key(const uint8_t *bytes, int32_t len)
{
    BIO *bio = BIO_new_mem_buf(bytes, len);
    if (!bio) return nullptr;
    // Try DER format first
    EVP_PKEY *key = d2i_PrivateKey_bio(bio, nullptr);
    if (!key) {
        // Fall back to PEM format
        (void)BIO_reset(bio);
        key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    }
    BIO_free(bio);
    return key;
}

extern "C" {

int native_bridge_pkcs12_extract(
    const uint8_t *p12_bytes,
    int32_t p12_len,
    const char *password,
    uint8_t **out_cert,
    int32_t *out_cert_len,
    uint8_t **out_key,
    int32_t *out_key_len)
{
    BIO *bio = BIO_new_mem_buf(p12_bytes, p12_len);
    PKCS12 *p12 = d2i_PKCS12_bio(bio, nullptr);
    BIO_free(bio);
    if (!p12)
    {
        return -1;
    }

    EVP_PKEY *key = nullptr;
    X509 *cert = nullptr;

    bool parsed = false;
    const char *passwords[] = { password, "", nullptr };
    bool tried_null = false;
    bool tried_empty = false;
    
    for (const char *pass : passwords)
    {
        if (pass == nullptr)
        {
            if (tried_null) continue;
            tried_null = true;
        }
        else if (strcmp(pass, "") == 0)
        {
            if (tried_empty) continue;
            tried_empty = true;
        }
        
        parsed = PKCS12_parse(p12, pass, &key, &cert, nullptr);
        if (parsed) break;
    }

    if (!parsed)
    {
        unsigned long err = ERR_get_error();
        int reason = ERR_GET_REASON(err);
        PKCS12_free(p12);
        
        if (reason == PKCS12_R_MAC_VERIFY_FAILURE || reason == PKCS12_R_MAC_GENERATION_ERROR)
        {
            return -2;
        }
        return -3;
    }

    BIO *certBIO = BIO_new(BIO_s_mem());
    BIO *keyBIO  = BIO_new(BIO_s_mem());

    PEM_write_bio_X509(certBIO, cert);
    PEM_write_bio_PrivateKey(keyBIO, key, nullptr, nullptr, 0, nullptr, nullptr);

    *out_cert = nb_copy_bio(certBIO, out_cert_len);
    *out_key  = nb_copy_bio(keyBIO,  out_key_len);

    BIO_free(certBIO);
    BIO_free(keyBIO);
    EVP_PKEY_free(key);
    X509_free(cert);
    PKCS12_free(p12);

    return 1;
}

int native_bridge_x509_parse(
    const uint8_t *pem_bytes,
    int32_t pem_len,
    char **out_name,
    char **out_serial)
{
    X509 *cert = read_cert(pem_bytes, pem_len);
    if (!cert) return 0;

    X509_NAME *subject = X509_get_subject_name(cert);
    int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx == -1) {
        X509_free(cert);
        return 0;
    }

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, idx);
    ASN1_STRING *nameData = X509_NAME_ENTRY_get_data(entry);

    const unsigned char *cname =
        ASN1_STRING_get0_data(nameData);

    ASN1_INTEGER *serialASN = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serialASN, nullptr);
    char *hex = BN_bn2hex(bn);

    *out_name = strdup((const char *)cname);
    *out_serial = strdup(hex);

    BN_free(bn);
    OPENSSL_free(hex);
    X509_free(cert);

    return 1;
}

int native_bridge_pkcs12_create(
    const uint8_t *cert_bytes,
    int32_t cert_len,
    const uint8_t *key_bytes,
    int32_t key_len,
    const char *password,
    uint8_t **out_p12,
    int32_t *out_p12_len)
{
    X509 *cert = read_cert(cert_bytes, cert_len);
    EVP_PKEY *key = read_private_key(key_bytes, key_len);

    if (!cert || !key) {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
        return 0;
    }

    PKCS12 *p12 =
        PKCS12_create(password, "", key, cert, nullptr, 0,0,0,0,0);

    BIO *out = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(out, p12);

    *out_p12 = nb_copy_bio(out, out_p12_len);

    BIO_free(out);
    PKCS12_free(p12);
    EVP_PKEY_free(key);
    X509_free(cert);

    return 1;
}
int native_bridge_generate_csr(
    const char *country,
    const char *state,
    const char *locality,
    const char *organization,
    const char *common_name,
    uint8_t **out_csr,
    int32_t *out_csr_len,
    uint8_t **out_key,
    int32_t *out_key_len,
    char **out_error)
{
    auto fail = [&](const char *msg) -> int {
        if (out_error) *out_error = strdup(msg);
        return 0;
    };

    BIGNUM *bignum = BN_new();
    RSA *rsa = RSA_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    X509_REQ *req = X509_REQ_new();

    if (!bignum || !rsa || !pkey || !req) {
        if (bignum) BN_free(bignum);
        if (rsa) RSA_free(rsa);
        if (pkey) EVP_PKEY_free(pkey);
        if (req) X509_REQ_free(req);
        return fail("allocation failed");
    }

    if (!BN_set_word(bignum, RSA_F4)) {
        BN_free(bignum);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        return fail("BN_set_word failed");
    }

    if (!RSA_generate_key_ex(rsa, 2048, bignum, nullptr)) {
        BN_free(bignum);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        return fail("RSA_generate_key_ex failed");
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    rsa = nullptr;

    if (!X509_REQ_set_version(req, 1)) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        BN_free(bignum);
        return fail("set_version failed");
    }

    X509_NAME *name = X509_REQ_get_subject_name(req);

    auto add = [&](const char *k, const char *v) -> bool {
        return X509_NAME_add_entry_by_txt(
            name,
            k,
            MBSTRING_ASC,
            (const unsigned char *)v,
            -1, -1, 0
        ) == 1;
    };

    if (!add("C", country) ||
        !add("ST", state) ||
        !add("L", locality) ||
        !add("O", organization) ||
        !add("CN", common_name)) {

        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        BN_free(bignum);
        return fail("subject build failed");
    }

    if (!X509_REQ_set_pubkey(req, pkey)) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        BN_free(bignum);
        return fail("set_pubkey failed");
    }

    if (X509_REQ_sign(req, pkey, EVP_sha1()) <= 0) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        BN_free(bignum);
        return fail("sign failed");
    }

    BIO *csrBIO = BIO_new(BIO_s_mem());
    BIO *keyBIO = BIO_new(BIO_s_mem());

    if (!csrBIO || !keyBIO) {
        if (csrBIO) BIO_free(csrBIO);
        if (keyBIO) BIO_free(keyBIO);
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        BN_free(bignum);
        return fail("BIO allocation failed");
    }

    if (!PEM_write_bio_X509_REQ(csrBIO, req) ||
        !PEM_write_bio_PrivateKey(
            keyBIO,
            pkey,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr)) {

        BIO_free(csrBIO);
        BIO_free(keyBIO);
        EVP_PKEY_free(pkey);
        X509_REQ_free(req);
        BN_free(bignum);
        return fail("PEM write failed");
    }

    *out_csr = nb_copy_bio(csrBIO, out_csr_len);
    *out_key = nb_copy_bio(keyBIO, out_key_len);

    BIO_free(csrBIO);
    BIO_free(keyBIO);
    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    BN_free(bignum);

    return 1;
}

}
