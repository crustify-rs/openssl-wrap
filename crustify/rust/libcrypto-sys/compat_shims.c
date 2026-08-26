#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include "crypto/asn1.h"
#include "crypto/evp/evp_local.h"
#include "internal/bio.h"

int crustify_ASN1_STRING_length(const ASN1_STRING *string)
{
    return string->length;
}

void crustify_ASN1_STRING_length_set(ASN1_STRING *string, int length)
{
    string->length = length;
}

/*
 * Reproduces ASN1_STRING_set(), which the no-deprecated build does not export.
 * It is ossl_asn1_string_set_internal() with add_nul_byte=1, so the allocation
 * is length + 1 and the reported length excludes the terminator; the original
 * rejects a length whose allocation would exceed INT_MAX, which is length
 * values from INT_MAX up. The explicit length argument replaces the C
 * function's len == -1 strlen() convention, which ASN1_STRING_set1_string()
 * already covers.
 */
int crustify_ASN1_STRING_set(ASN1_STRING *string, const unsigned char *data,
    size_t length)
{
    unsigned char *copy;

    if (length >= INT_MAX)
        return 0;
    copy = OPENSSL_malloc(length + 1);
    if (copy == NULL)
        return 0;
    if (length != 0)
        memcpy(copy, data, length);
    copy[length] = '\0';
    ASN1_STRING_set0(string, copy, (int)length);
    /* ossl_asn1_bit_string_clear_unused_bits(): the 0x07 count and its flag. */
    string->flags &= ~(0x07 | ASN1_STRING_FLAG_BITS_LEFT);
    return 1;
}

/*
 * EVP_MAC_CTX_dup() calls the provider's optional dupctx dispatch directly.
 * Check it before the safe Rust wrapper enters that public routine.
 */
int crustify_EVP_MAC_CTX_can_dup(const EVP_MAC_CTX *ctx)
{
    return ctx != NULL && ctx->meth != NULL && ctx->meth->dupctx != NULL;
}

typedef int (*crustify_BIO_mmsg_fn)(BIO *, BIO_MSG *, size_t, size_t,
    uint64_t, size_t *);

crustify_BIO_mmsg_fn crustify_BIO_meth_get_recvmmsg(const BIO_METHOD *method)
{
    return method->brecvmmsg;
}

crustify_BIO_mmsg_fn crustify_BIO_meth_get_sendmmsg(const BIO_METHOD *method)
{
    return method->bsendmmsg;
}

#if defined(OPENSSL_NO_DEPRECATED_4_1)
/* Internal replacements exported by the no-deprecated libcrypto build. */
int ossl_x509_check_host(const X509 *x, const char *chk, size_t chklen,
    unsigned int flags, char **peername);
int ossl_x509_check_rfc822(X509 *x, const char *chk, size_t chklen,
    unsigned int flags);
int ossl_x509_check_smtputf8(X509 *x, const char *chk, size_t chklen,
    unsigned int flags);
int ossl_x509_check_ip(const X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags);

int X509_check_host(const X509 *x, const char *chk, size_t chklen,
    unsigned int flags, char **peername)
{
    return ossl_x509_check_host(x, chk, chklen, flags, peername);
}

int X509_check_email(const X509 *x, const char *chk, size_t chklen,
    unsigned int flags)
{
    int ret;

    if (chk == NULL)
        return -2;
    if (chklen == 0)
        chklen = strlen(chk);
    else if (memchr(chk, '\0', chklen > 1 ? chklen - 1 : chklen))
        return -2;
    if (chklen > 1 && chk[chklen - 1] == '\0')
        --chklen;
    ret = ossl_x509_check_rfc822((X509 *)x, chk, chklen, flags);

    if (ret == 1)
        return 1;
    return ossl_x509_check_smtputf8((X509 *)x, chk, chklen, flags);
}

int X509_check_ip(const X509 *x, const unsigned char *chk, size_t chklen,
    unsigned int flags)
{
    return ossl_x509_check_ip(x, chk, chklen, flags);
}

int X509_check_ip_asc(const X509 *x, const char *ipasc, unsigned int flags)
{
    ASN1_OCTET_STRING *ip;
    int ret;

    if (ipasc == NULL || (ip = a2i_IPADDRESS(ipasc)) == NULL)
        return -2;
    ret = ossl_x509_check_ip(x, ASN1_STRING_get0_data(ip),
        (size_t)ASN1_STRING_get_length(ip), flags);
    ASN1_OCTET_STRING_free(ip);
    return ret;
}
#endif
