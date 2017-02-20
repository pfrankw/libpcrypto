#ifndef PCRYPTO_PK_H
#define PCRYPTO_PK_H

#include <mbedtls/pk.h>
#include <pcrypto/random.h>

#define PCRYPTO_PK_RSA_MAX_KEY_LEN 8192
#define PCRYPTO_PK_RSA_HASH_LEN 32

#define pcrypto_ecc_group_id mbedtls_ecp_group_id

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_pk_s {
    mbedtls_pk_context ctx;
    pcrypto_random_t random;
} pcrypto_pk_t;


int   pcrypto_pk_rsa_init_gen   ( pcrypto_pk_t *pk, int bits );
int   pcrypto_pk_init_pk        ( pcrypto_pk_t *pk, mbedtls_pk_context *mbed_pk, int pub );
int   pcrypto_pk_init_pemder    ( pcrypto_pk_t *pk, uint8_t *pem_or_der, size_t len, int pub );
void  pcrypto_pk_free           ( pcrypto_pk_t *pk );

int   pcrypto_pk_to_der         ( pcrypto_pk_t *pk, uint8_t *der, size_t len, int pub );
int   pcrypto_pk_to_pem         ( pcrypto_pk_t *pk, uint8_t *pem, size_t len, int pub );

int   pcrypto_pk_pub_encrypt    ( pcrypto_pk_t *pk, uint8_t *input, uint8_t *output, size_t *len );

int   pcrypto_pk_verify         ( pcrypto_pk_t *pk, uint8_t *msg_digest, uint8_t *sig, size_t siglen );
int   pcrypto_pk_verify_data    ( pcrypto_pk_t *pk, uint8_t *data, size_t data_len, uint8_t *sig, size_t sig_len );

int   pcrypto_pk_sign           ( pcrypto_pk_t *pk, uint8_t *hash, uint8_t *sig, size_t *sig_len );
int   pcrypto_pk_sign_data      ( pcrypto_pk_t *pk, uint8_t *data, size_t len, uint8_t *sig, size_t *sig_len );

int   pcrypto_pk_hash           ( pcrypto_pk_t *pk, uint8_t *digest );

#ifdef __cplusplus
}
#endif

#endif
