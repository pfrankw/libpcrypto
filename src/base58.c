#include <string.h>

#include "pcrypto/base58.h"
#include "libbase58.h"

int pcrypto_base58_encode( char *base58, size_t base58_len, void *in_data, size_t in_data_len ){
    if( b58enc( base58, &base58_len, in_data, in_data_len ) )
        return 0;
    return -1;
}

int pcrypto_base58_decode( const char *base58, uint8_t *out_data, size_t *out_data_len ){

    size_t out_data_len_orig = *out_data_len;
    bool r;

    r = b58tobin( out_data, out_data_len, base58, 0 );

    if( !r )
        return -1;

    memcpy( out_data, &out_data[out_data_len_orig-*out_data_len], *out_data_len ); //Moving the data from the end of the buffer to the start of it
    memset( &out_data[*out_data_len], 0, out_data_len_orig-*out_data_len ); //Clearing the old data at the end

    return 0;
}
