#ifndef PCRYPTO_SHA1_H
#define PCRYPTO_SHA1_H

#include <stdint.h>

#include <mbedtls/sha1.h>

#define PCRYPTO_SHA1_LEN 20

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_sha1_s {
    mbedtls_sha1_context ctx;
} pcrypto_sha1_t;

void  pcrypto_sha1_init   ( pcrypto_sha1_t *sha1 );
void  pcrypto_sha1_free   ( pcrypto_sha1_t *sha1 );
void  pcrypto_sha1_update ( pcrypto_sha1_t *sha1, void *data, size_t len ); /* The digest updating function */
void  pcrypto_sha1_finish ( pcrypto_sha1_t *sha1, uint8_t *digest ); /* This generates the final digest. NOTE: digest array must be at least PCRYPTO_SHA1_LEN bytes */
void  pcrypto_sha1        ( void *data, size_t len, uint8_t *digest ); /* Fast hashing function that requires no ctx */

#ifdef __cplusplus
}
#endif

#endif
