#include <stdio.h>
#include <string.h>

#include <pcrypto/aes.h>

#define KEY_SIZE 256
#define TEST_STR "I topi non avevano nipoti"
#define TEST_CRYPT_RESULT "\x77\x6d\x12\xa8\x69\xfc\x6e\x04\xf2\x4b\xb3\xe6\x11\xd3\x82\x24\xde\xc0\x9e\x8b\x04\xfd\x92\xea\x5e"
static const uint8_t TEST_KEY[] = { 0x17, 0x0e, 0xab, 0x89, 0xcf, 0x08, 0x2d, 0xee, 0xaf, 0x6f, 0x58, 0x35, 0xb0, 0x4a, 0xba, 0x32, 0x97, 0x0d, 0xf3, 0x08, 0xe6, 0x9c, 0xf6, 0x98, 0xd9, 0x16, 0xe4, 0xa9, 0x04, 0xd3, 0x0e, 0xdd };


int main(){

    int i = 0;
    pcrypto_aes_t aes = {{0}};
    char str[100];
    size_t len = 0;

    if( pcrypto_aes_init( &aes, KEY_SIZE, TEST_KEY ) != 0 )
        goto exit;

    strncpy( str, TEST_STR, sizeof( str ) );
    len = strlen( str );

    pcrypto_aes_crypt_ctr( &aes, str, str, len );

    printf( "The crypt result is: " );
    for( i=0; i<len; i++ )
        printf( "%02x", (uint8_t)str[i] );
    printf( "\n" );


exit:
    pcrypto_aes_free( &aes );
    return memcmp( str, TEST_CRYPT_RESULT, len );
}
