#ifndef PCRYPTO_AES_H
#define PCRYPTO_AES_H

#include <mbedtls/aes.h>

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_aes_s {
    mbedtls_aes_context ctx;
    size_t nc_off;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
} pcrypto_aes_t;


int   pcrypto_aes_init      ( pcrypto_aes_t *aes, int bits, const uint8_t *key );
void  pcrypto_aes_free      ( pcrypto_aes_t *aes );
void  pcrypto_aes_crypt_ctr ( pcrypto_aes_t *aes, void *input, void *output, size_t len );

#ifdef __cplusplus
}
#endif

#endif
