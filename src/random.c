#include <string.h>
#include "pcrypto/random.h"

int pcrypto_random_init( pcrypto_random_t *random, const char *custom ){

    int r = -1;

    if( !random ) /* L O L */
        goto exit;

    memset( random, 0, sizeof( pcrypto_random_t ) );

    mbedtls_entropy_init( &random->entropy );
    mbedtls_ctr_drbg_init( &random->ctr_drbg );

    if( mbedtls_ctr_drbg_seed( &random->ctr_drbg, mbedtls_entropy_func, &random->entropy, (unsigned char*)custom, custom ? strlen( custom ) : 0 ) != 0 )
        goto exit;

    r = 0;
exit:
    return r;

}


void pcrypto_random_free( pcrypto_random_t *random ){

    if( !random )
        return;

    mbedtls_ctr_drbg_free( &random->ctr_drbg );
    mbedtls_entropy_free( &random->entropy );
    memset( random, 0, sizeof( pcrypto_random_t ) );

}

void pcrypto_random_bytes( void *bytes, size_t len ){

    pcrypto_random_t random;

    if( !bytes || !len )
        return;

    if( pcrypto_random_init( &random, 0 ) != 0 )
        goto exit;

    if( mbedtls_ctr_drbg_random( &random.ctr_drbg, bytes, len ) != 0 )
        goto exit;

exit:
    pcrypto_random_free( &random );
}

uint32_t pcrypto_random_uint32( uint32_t min, uint32_t max ){

    uint32_t ret;

    pcrypto_random_bytes( &ret, sizeof( ret ) );

    return min + ( ret%( 1+max-min ) );
}
