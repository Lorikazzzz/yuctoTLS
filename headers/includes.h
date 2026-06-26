#ifndef INCLUDES_H
#define INCLUDES_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/random.h>

/* Standard Debug Macro mapping to standard printf when DEBUG is defined */
#ifdef DEBUG
#define debug(fmt, ...) do { \
    printf(fmt, ##__VA_ARGS__); \
} while (0)
#else
#define debug(...)
#endif

/* Secure PRNG generation function */
int bot_prng_generate_block(unsigned char *output, unsigned int sz);

#endif /* INCLUDES_H */
