#ifndef PCRYPTO_BASE64_H
#define PCRYPTO_BASE64_H


#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C"  {
#endif


int   pcrypto_base64_encode ( char *base64, size_t base64_len, void *in_data, size_t in_data_len );
int   pcrypto_base64_decode ( const char *base64, void *out_data, size_t *out_data_len );



#ifdef __cplusplus
}
#endif

#endif
