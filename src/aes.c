#include <string.h>

#include "pcrypto/aes.h"


int pcrypto_aes_init( pcrypto_aes_t *aes, int bits, const uint8_t *key ){

    if( !aes || !bits || bits%128 != 0 || bits > 256 || !key )
        return -1;

    memset( aes, 0, sizeof( pcrypto_aes_t ) );
    mbedtls_aes_init( &aes->ctx );
    mbedtls_aes_setkey_enc( &aes->ctx, key, bits );

    return 0;
}

void pcrypto_aes_free( pcrypto_aes_t *aes ){
    if( !aes )
        return;
    mbedtls_aes_free( &aes->ctx );
    memset( aes, 0, sizeof( pcrypto_aes_t ) );
}

void pcrypto_aes_crypt_ctr( pcrypto_aes_t *aes, void *input, void *output, size_t len ){

    if( !aes || !input || !output || !len )
        return;

    mbedtls_aes_crypt_ctr( &aes->ctx, len, &aes->nc_off, aes->nonce_counter, aes->stream_block, input, output );

}
