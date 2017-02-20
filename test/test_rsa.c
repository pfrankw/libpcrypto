#include <stdio.h>
#include <string.h>

#include <pcrypto/pk.h>
#include <pcrypto/sha256.h>

#define KEY_SIZE 2048
#define TEST_STR "I topi non avevano nipoti"
#define TEST_STR_DIGEST "\x25\xad\xa6\xb3\x72\x9d\xb7\xfe\xba\x74\x55\xc9\xc4\xfb\x2b\xbc\x36\xea\xaa\x3d"


int main(){

    int i = 0;
    pcrypto_pk_t pk;
    uint8_t sign[( KEY_SIZE+7 )/8];
    uint8_t key_hash[PCRYPTO_PK_RSA_HASH_LEN];
    size_t sig_len = 0;

    if( pcrypto_pk_rsa_init_gen( &pk, KEY_SIZE ) != 0 )
        goto exit;

    if( pcrypto_pk_sign_data( &pk, (uint8_t*)TEST_STR, strlen( TEST_STR ), sign, &sig_len ) != 0 )
        goto exit;

    if( pcrypto_pk_hash( &pk, key_hash ) != 0 )
        goto exit;

    printf( "The key hash is: " );
    for( i=0; i<PCRYPTO_PK_RSA_HASH_LEN; i++ )
        printf( "%02x", key_hash[i] );
    printf( "\n" );

    printf( "The result signature is: " );
    for( i=0; i<sig_len; i++ )
        printf( "%02x", sign[i] );
    printf( "\n" );


exit:
    i = pcrypto_pk_verify_data( &pk, (uint8_t*)TEST_STR, strlen( TEST_STR ), sign, sizeof( sign ) );
    pcrypto_pk_free( &pk );
    return i;

}
