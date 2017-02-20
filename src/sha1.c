#include "pcrypto/sha1.h"


void pcrypto_sha1_init( pcrypto_sha1_t *sha1 ){
    mbedtls_sha1_init( &sha1->ctx );
}

void pcrypto_sha1_free( pcrypto_sha1_t *sha1 ){
    mbedtls_sha1_free( &sha1->ctx );
}

void pcrypto_sha1_update( pcrypto_sha1_t *sha1, void *data, size_t len ){
    mbedtls_sha1_update( &sha1->ctx, data, len );
}

void pcrypto_sha1_finish( pcrypto_sha1_t *sha1, uint8_t *digest ){
    mbedtls_sha1_finish( &sha1->ctx, digest );
}

void pcrypto_sha1( void *data, size_t len, uint8_t *digest ){
    mbedtls_sha1( data, len, digest );
}
