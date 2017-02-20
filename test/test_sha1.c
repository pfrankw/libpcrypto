#include <stdio.h>
#include <string.h>

#include <pcrypto/sha1.h>

#define TEST_STR "I topi non avevano nipoti"
#define TEST_STR_DIGEST "\x25\xad\xa6\xb3\x72\x9d\xb7\xfe\xba\x74\x55\xc9\xc4\xfb\x2b\xbc\x36\xea\xaa\x3d"


int main(){

    int i = 0;
    pcrypto_sha1_t sha1;
    uint8_t digest[PCRYPTO_SHA1_LEN];

    pcrypto_sha1_init( &sha1 );
    pcrypto_sha1_update( &sha1, (uint8_t*)TEST_STR, strlen( TEST_STR ) );
    pcrypto_sha1_finish( &sha1, digest );
    pcrypto_sha1_free( &sha1 );

    printf( "The result digest is: " );
    for( i=0; i<PCRYPTO_SHA1_LEN; i++ )
        printf( "%02x", digest[i] );
    printf( "\n" );

    return memcmp( digest, TEST_STR_DIGEST, PCRYPTO_SHA1_LEN );

}
