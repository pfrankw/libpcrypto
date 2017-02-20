#ifndef PCRYPTO_BASE58_H
#define PCRYPTO_BASE58_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C"  {
#endif

int   pcrypto_base58_encode ( char *base58, size_t base58_len, void *in_data, size_t in_data_len );
int   pcrypto_base58_decode ( const char *base58, uint8_t *out_data, size_t *out_data_len );

#ifdef __cplusplus
}
#endif

#endif
