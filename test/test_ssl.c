#include <stdio.h>
#include <pcrypto/ssl.h>

#define SSL_DOMAIN "www.google.com"
#define SSL_PORT "443"

int main(){

    int r = -1, rr = 0;
    mbedtls_net_context net = {0};
    pcrypto_ssl_t ssl;
    char buffer[1024];

    if( mbedtls_net_connect( &net, SSL_DOMAIN, SSL_PORT, MBEDTLS_NET_PROTO_TCP ) != 0 )
        goto exit;

    if( pcrypto_ssl_init( &ssl, net.fd, 0, 0, 0, 0, 0 ) != 0 )
        goto exit;

    if( pcrypto_ssl_write( &ssl, "GET / HTTP/1.1\r\n\r\n", 18 ) != 18 )
        goto exit;

    while( ( rr=pcrypto_ssl_read( &ssl, buffer, 1024 ) ) == MBEDTLS_ERR_SSL_WANT_READ )
        mbedtls_net_usleep( 50*1000 );

    if( rr <= 0 )
        goto exit;

    buffer[rr] = 0;
    printf( "%s", buffer );

    r = 0;
exit:

    pcrypto_ssl_free( &ssl );
    mbedtls_net_free( &net );
    return r;
}
