#ifndef PCRYPTO_SSL_H
#define PCRYPTO_SSL_H

#include <mbedtls/ssl.h>
#include <mbedtls/net.h>

#include <pcrypto/random.h>
#include <pcrypto/x509.h>

#ifdef __cplusplus
extern "C"  {
#endif

typedef struct pcrypto_ssl_s {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_net_context net;
    pcrypto_random_t random;
    pcrypto_pk_t *pk;
    pcrypto_pk_t remote_pk;
    pcrypto_x509_t remote_crt;
    pcrypto_x509_t local_crt;

} pcrypto_ssl_t;

int   pcrypto_ssl_init  ( pcrypto_ssl_t *ssl, int fd, uint32_t read_msec_timeout, pcrypto_pk_t *pk, const char *cn, const char *org, const char *cc );
void  pcrypto_ssl_free  ( pcrypto_ssl_t *ssl );

int   pcrypto_ssl_write ( pcrypto_ssl_t *ssl, void *buf, size_t len );
int   pcrypto_ssl_read  ( pcrypto_ssl_t *ssl, void *buf, size_t len );


#ifdef __cplusplus
}
#endif

#endif
