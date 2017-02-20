#include <stdio.h>
#include <string.h>

#include <pcrypto/base58.h>

#define TEST_STR "Qmcpo2iLBikrdf1d6QU6vXuNb6P7hwrbNPW9kLAH8eG67z"

int main(){

    int i;
    char base58[100];
    uint8_t data[50];
    size_t data_len = 50, base58_len = 100;

    if( pcrypto_base58_decode( TEST_STR, data, &data_len ) != 0 )
        return -1;

    for( i=0; i<data_len; i++ )
        printf( "%02x", data[i] );
    printf( "\n" );

    if( pcrypto_base58_encode( base58, base58_len, data, data_len ) != 0 )
        return -1;

    printf( "%s\n", base58 );

    return strcmp( base58, TEST_STR );

}
