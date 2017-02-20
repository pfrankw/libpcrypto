#ifndef PCRYPTO_SHA256_H
#define PCRYPTO_SHA256_H

#include <stdint.h>

#include <mbedtls/sha256.h>


#define PCRYPTO_SHA256_LEN 32

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_sha256_s {
    mbedtls_sha256_context ctx;
} pcrypto_sha256_t;

void  pcrypto_sha256_init   ( pcrypto_sha256_t *sha256 );
void  pcrypto_sha256_free   ( pcrypto_sha256_t *sha256 );
void  pcrypto_sha256_update ( pcrypto_sha256_t *sha256, void *data, size_t len ); /* The digest updating function */
void  pcrypto_sha256_finish ( pcrypto_sha256_t *sha256, uint8_t *digest ); /* This generates the final digest. NOTE: digest array must be at least PCRYPTO_SHA256_LEN bytes */
void  pcrypto_sha256        ( void *data, size_t len, uint8_t *digest ); /* Fast hashing function that requires no ctx */

#ifdef __cplusplus
}
#endif

#endif
