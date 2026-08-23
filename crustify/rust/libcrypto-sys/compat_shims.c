#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include "crypto/asn1.h"
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
