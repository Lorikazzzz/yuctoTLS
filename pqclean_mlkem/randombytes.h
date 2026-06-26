#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H
#include <stddef.h>
#include <stdint.h>
int bot_prng_generate_block(unsigned char *output, unsigned int sz);
static inline void randombytes(uint8_t *out, size_t n) {
    bot_prng_generate_block(out, (unsigned int)n);
}
#endif
