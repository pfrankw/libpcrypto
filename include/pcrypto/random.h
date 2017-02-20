#ifndef PCRYPTO_RANDOM_H
#define PCRYPTO_RANDOM_H


#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>


#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_random_s {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} pcrypto_random_t;


int pcrypto_random_init( pcrypto_random_t *random, const char *custom );
void pcrypto_random_free( pcrypto_random_t *random );
void pcrypto_random_bytes( void *bytes, size_t len );
uint32_t pcrypto_random_uint32( uint32_t min, uint32_t max );

#ifdef __cplusplus
}
#endif

#endif
