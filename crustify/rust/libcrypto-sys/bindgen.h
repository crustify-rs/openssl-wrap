/* crustify:includes:start */
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/objects.h>
#include <openssl/stack.h>
#include <internal/bio.h>
#include "internal/bio_addr.h"
/* crustify:includes:end */

/* crustify:macros:start */
#if defined(OPENSSL_NO_DEPRECATED_3_0)
typedef long (*crustify_BIO_callback_fn)(BIO *b, int oper,
    const char *argp, int argi, long argl, long ret);
void BIO_set_callback(BIO *b, crustify_BIO_callback_fn callback);
#endif
/* crustify:macros:end */

/* crustify:compat-shims:start */
int crustify_ASN1_STRING_length(const ASN1_STRING *string);
void crustify_ASN1_STRING_length_set(ASN1_STRING *string, int length);
int crustify_ASN1_STRING_set(ASN1_STRING *string, const unsigned char *data,
    size_t length);
/* crustify:compat-shims:end */
