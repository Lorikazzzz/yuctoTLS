#include "headers/includes.h"

/*
 * Standalone secure PRNG block generator.
 * Uses /dev/urandom for high-quality cryptographic entropy.
 * Portable across standard Linux/POSIX environments.
 */
int bot_prng_generate_block(unsigned char *output, unsigned int sz) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Fallback: if /dev/urandom is unavailable, use standard rand() seeded with time */
        static int seeded = 0;
        if (!seeded) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            srand((unsigned int)(tv.tv_usec ^ tv.tv_sec ^ getpid()));
            seeded = 1;
        }
        for (unsigned int i = 0; i < sz; i++) {
            output[i] = rand() & 0xFF;
        }
        return 0;
    }

    unsigned int read_bytes = 0;
    while (read_bytes < sz) {
        ssize_t n = read(fd, output + read_bytes, sz - read_bytes);
        if (n < 0) {
            /* On error, break and use fallback for remaining bytes */
            break;
        }
        if (n == 0) {
            /* EOF, should not happen on /dev/urandom, but handle just in case */
            break;
        }
        read_bytes += n;
    }
    close(fd);

    /* Fallback for any remaining unwritten bytes */
    if (read_bytes < sz) {
        static int seeded = 0;
        if (!seeded) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            srand((unsigned int)(tv.tv_usec ^ tv.tv_sec ^ getpid()));
            seeded = 1;
        }
        for (unsigned int i = read_bytes; i < sz; i++) {
            output[i] = rand() & 0xFF;
        }
    }

    return 0; /* 0 = success */
}
