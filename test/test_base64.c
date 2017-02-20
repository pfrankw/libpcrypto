#include <stdio.h>
#include <string.h>

#include <pcrypto/base64.h>

#define TEST_STR "SSB0b3BpIG5vbiBhdmV2YW5vIG5pcG90aQ=="

int main(){

    int i;
    char base64[100];
    uint8_t data[50];
    size_t data_len = 50, base64_len = 100;

    if( pcrypto_base64_decode( TEST_STR, data, &data_len ) != 0 )
        return -1;

    for( i=0; i<data_len; i++ )
        printf( "%02x", data[i] );
    printf( "\n" );

    if( pcrypto_base64_encode( base64, base64_len, data, data_len ) != 0 )
        return -1;

    printf( "%s\n", base64 );

    return strcmp( base64, TEST_STR );

}
