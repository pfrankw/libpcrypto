#include "pcrypto/sha256.h"


void pcrypto_sha256_init( pcrypto_sha256_t *sha256 ){
    mbedtls_sha256_init( &sha256->ctx );
}

void pcrypto_sha256_free( pcrypto_sha256_t *sha256 ){
    mbedtls_sha256_free( &sha256->ctx );
}

void pcrypto_sha256_update( pcrypto_sha256_t *sha256, void *data, size_t len ){
    mbedtls_sha256_update( &sha256->ctx, data, len );
}

void pcrypto_sha256_finish( pcrypto_sha256_t *sha256, uint8_t *digest ){
    mbedtls_sha256_finish( &sha256->ctx, digest );
}

void pcrypto_sha256( void *data, size_t len, uint8_t *digest ){
    mbedtls_sha256( data, len, digest, 0 );
}
