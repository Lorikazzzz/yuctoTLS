#include "headers/includes.h"

int bot_prng_generate_block(unsigned char *output, unsigned int sz) {
    size_t done = 0;
    while (done < sz) {
        ssize_t n = getrandom(output + done, sz - done, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}
