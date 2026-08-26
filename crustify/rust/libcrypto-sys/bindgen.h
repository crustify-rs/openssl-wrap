/* crustify:includes:start */
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/core.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/hpke.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <internal/bio.h>
#include "internal/bio_addr.h"
/* crustify:includes:end */

/* crustify:macros:start */
#if defined(OPENSSL_NO_DEPRECATED_3_0)
typedef long (*crustify_BIO_callback_fn)(BIO *b, int oper,
    const char *argp, int argi, long argl, long ret);
void BIO_set_callback(BIO *b, crustify_BIO_callback_fn callback);
int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **ukm);
int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
typedef struct dsa_st DSA;
DSA *DSA_new(void);
void DSA_free(DSA *dsa);
int DSA_up_ref(DSA *dsa);
DSA *DSAparams_dup(const DSA *dsa);
typedef struct ec_key_st EC_KEY;
EC_KEY *EC_KEY_new(void);
void EC_KEY_free(EC_KEY *key);
EC_KEY *EC_KEY_dup(const EC_KEY *key);
int EC_KEY_up_ref(EC_KEY *key);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
typedef struct dh_st DH;
DH *DH_new(void);
void DH_free(DH *dh);
int DH_up_ref(DH *dh);
DH *DHparams_dup(const DH *dh);
const DH *EVP_PKEY_get0_DH(const EVP_PKEY *pkey);
DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *key);
typedef struct rsa_st RSA;
RSA *RSA_new(void);
void RSA_free(RSA *rsa);
int RSA_up_ref(RSA *rsa);
const DSA *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey);
DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
const RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
    size_t len, const EVP_CIPHER *cipher);
const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx);
const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx);
unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx);
#endif
#if defined(OPENSSL_NO_DEPRECATED_4_1)
int EVP_CIPHER_CTX_get_num(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num);
#endif
/* crustify:macros:end */

/* crustify:compat-shims:start */
int crustify_ASN1_STRING_length(const ASN1_STRING *string);
void crustify_ASN1_STRING_length_set(ASN1_STRING *string, int length);
int crustify_ASN1_STRING_set(ASN1_STRING *string, const unsigned char *data,
    size_t length);
typedef int (*crustify_BIO_mmsg_fn)(BIO *, BIO_MSG *, size_t, size_t,
    uint64_t, size_t *);
crustify_BIO_mmsg_fn crustify_BIO_meth_get_recvmmsg(const BIO_METHOD *method);
crustify_BIO_mmsg_fn crustify_BIO_meth_get_sendmmsg(const BIO_METHOD *method);
#if defined(OPENSSL_NO_DEPRECATED_4_0)
int X509_NAME_get_text_by_NID(const X509_NAME *name, int nid,
    char *buf, int len);
int X509_NAME_get_text_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj,
    char *buf, int len);
#endif
#if defined(OPENSSL_NO_DEPRECATED_4_1)
int X509_check_host(const X509 *x, const char *chk, size_t chklen,
    unsigned int flags, char **peername);
int X509_check_email(const X509 *x, const char *chk, size_t chklen,
    unsigned int flags);
int X509_check_ip(const X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);
int X509_check_ip_asc(const X509 *x, const char *ipasc, unsigned int flags);
#endif
/* `no-deprecated` hides this still-linked compatibility declaration. */
int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *cipher);
/* crustify:compat-shims:end */
