#include <string.h>

#include <mbedtls/error.h>

#include "pcrypto/ssl.h"

int pcrypto_ssl_init( pcrypto_ssl_t *ssl, int fd, uint32_t read_msec_timeout, pcrypto_pk_t *pk, const char *cn, const char *org, const char *cc ){

    int r = -1, hr = 0;

    if( !ssl ) /* pk, cn, org and cc can be NULL */
        goto exit;

    memset( ssl, 0, sizeof( pcrypto_ssl_t ) );
    ssl->net.fd = fd;

    if( pcrypto_random_init( &ssl->random, 0 ) != 0 )
        goto exit;

    mbedtls_ssl_init( &ssl->ssl );

    mbedtls_ssl_config_init( &ssl->config );
    if( mbedtls_ssl_config_defaults( &ssl->config,
                                     pk ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
        goto exit;

    mbedtls_ssl_conf_rng( &ssl->config, mbedtls_ctr_drbg_random, &ssl->random.ctr_drbg );
    mbedtls_ssl_set_bio( &ssl->ssl, &ssl->net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    mbedtls_ssl_conf_read_timeout( &ssl->config, read_msec_timeout );
    mbedtls_ssl_conf_authmode( &ssl->config, MBEDTLS_SSL_VERIFY_NONE );

    if( pk ){
        ssl->pk = pk;

        if( pcrypto_x509_init_pk( &ssl->local_crt, pk, cn, org, cc ) != 0 )
            goto exit;

        mbedtls_ssl_conf_own_cert( &ssl->config, &ssl->local_crt.crt, &pk->ctx );
    }

    if( mbedtls_ssl_setup( &ssl->ssl, &ssl->config ) != 0 )
        goto exit;

    while( ( hr = mbedtls_ssl_handshake( &ssl->ssl ) ) != 0 )
        if( hr != MBEDTLS_ERR_SSL_WANT_READ && hr != MBEDTLS_ERR_SSL_WANT_WRITE )
            goto exit;

    if( !pk ){

        if( pcrypto_x509_init_x509( &ssl->remote_crt, mbedtls_ssl_get_peer_cert( &ssl->ssl ) ) != 0 )
            goto exit;

        if( pcrypto_x509_get_pk_pubkey( &ssl->remote_crt, &ssl->remote_pk ) != 0 )
            goto exit;
    }

    r = 0;
exit:
    if( r != 0 ) pcrypto_ssl_free( ssl );
    return r;
}


void pcrypto_ssl_free( pcrypto_ssl_t *ssl ){
    if( !ssl )
        return;

    mbedtls_ssl_close_notify( &ssl->ssl );
    pcrypto_random_free( &ssl->random );
    pcrypto_x509_free( &ssl->remote_crt );
    pcrypto_x509_free( &ssl->local_crt );
    pcrypto_pk_free( &ssl->remote_pk );
    mbedtls_ssl_free( &ssl->ssl );
    mbedtls_ssl_config_free( &ssl->config );
    memset( ssl, 0, sizeof( pcrypto_ssl_t ) );
}

int pcrypto_ssl_write( pcrypto_ssl_t *ssl, void *buf, size_t len ){
    return mbedtls_ssl_write( &ssl->ssl, buf, len );
}

int pcrypto_ssl_read( pcrypto_ssl_t *ssl, void *buf, size_t len ){
    return mbedtls_ssl_read( &ssl->ssl, buf, len );
}
