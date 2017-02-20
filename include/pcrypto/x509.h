#ifndef PCRYPTO_X509_H
#define PCRYPTO_X509_H

#include <mbedtls/x509_crt.h>

#include <pcrypto/pk.h>

#define PCRYPTO_X509_HASH_LEN 32
#define PCRYPTO_X509_SUBJECT_NAME_TEMPLATE "CN=%s,O=%s,C=%s"

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_x509_s {
    mbedtls_x509_crt crt;
} pcrypto_x509_t;

int   pcrypto_x509_init_pk        ( pcrypto_x509_t *x509, pcrypto_pk_t *pk, const char *cn, const char *org, const char *cc );
int   pcrypto_x509_init_x509      ( pcrypto_x509_t *x509, const mbedtls_x509_crt *crt );
int   pcrypto_x509_init_der       ( pcrypto_x509_t *x509, uint8_t *dercrt, size_t len );
void  pcrypto_x509_free           ( pcrypto_x509_t *x509 );
int   pcrypto_x509_get_pk_pubkey ( pcrypto_x509_t *x509, pcrypto_pk_t *pk );
int   pcrypto_x509_to_der         ( pcrypto_x509_t *x509, uint8_t *der, size_t *len );
int   pcrypto_x509_hash           ( pcrypto_x509_t *x509, uint8_t *hash );

#ifdef __cplusplus
}
#endif

#endif
