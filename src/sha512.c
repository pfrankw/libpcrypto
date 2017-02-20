#include "pcrypto/sha512.h"


void pcrypto_sha512_init( pcrypto_sha512_t *sha512 ){
    mbedtls_sha512_init( &sha512->ctx );
}

void pcrypto_sha512_free( pcrypto_sha512_t *sha512 ){
    mbedtls_sha512_free( &sha512->ctx );
}

void pcrypto_sha512_update( pcrypto_sha512_t *sha512, void *data, size_t len ){
    mbedtls_sha512_update( &sha512->ctx, data, len );
}

void pcrypto_sha512_finish( pcrypto_sha512_t *sha512, uint8_t *digest ){
    mbedtls_sha512_finish( &sha512->ctx, digest );
}

void pcrypto_sha512( void *data, size_t len, uint8_t *digest ){
    mbedtls_sha512( data, len, digest, 0 );
}
