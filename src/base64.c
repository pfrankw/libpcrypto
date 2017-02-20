#include <mbedtls/base64.h>

#include "pcrypto/base64.h"


int pcrypto_base64_encode( char *base64, size_t base64_len, void *in_data, size_t in_data_len ){
    return mbedtls_base64_encode( (unsigned char*)base64, base64_len, &base64_len, in_data, in_data_len );//Third parameter not used
}


int pcrypto_base64_decode( const char *base64, void *out_data, size_t *out_data_len ){
    return mbedtls_base64_decode( out_data, *out_data_len, out_data_len, (const unsigned char*)base64, strlen( base64 ) );
}
