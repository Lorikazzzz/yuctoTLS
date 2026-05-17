#ifndef __CHACHA20_H
#define __CHACHA20_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void chacha20_xor(uint8_t *key, uint32_t counter, uint8_t *nonce, char *input, char *output, int inputlen);

#ifdef __cplusplus
}
#endif

#endif
