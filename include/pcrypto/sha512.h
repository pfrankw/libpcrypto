#ifndef PCRYPTO_SHA512_H
#define PCRYPTO_SHA512_H

#include <stdint.h>

#include <mbedtls/sha512.h>


#define PCRYPTO_SHA512_LEN 64

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_sha512_s {
    mbedtls_sha512_context ctx;
} pcrypto_sha512_t;

void  pcrypto_sha512_init   ( pcrypto_sha512_t *sha512 );
void  pcrypto_sha512_free   ( pcrypto_sha512_t *sha512 );
void  pcrypto_sha512_update ( pcrypto_sha512_t *sha512, void *data, size_t len ); /* The digest updating function */
void  pcrypto_sha512_finish ( pcrypto_sha512_t *sha512, uint8_t *digest ); /* This generates the final digest. NOTE: digest array must be at least PCRYPTO_SHA512_LEN bytes */
void  pcrypto_sha512        ( void *data, size_t len, uint8_t *digest ); /* Fast hashing function that requires no ctx */

#ifdef __cplusplus
}
#endif

#endif
