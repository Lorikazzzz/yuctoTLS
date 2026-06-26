#ifndef PQCLEAN_COMMON_COMPAT_H
#define PQCLEAN_COMMON_COMPAT_H
#if defined(__GNUC__) || defined(__clang__)
#  define PQCLEAN_PREVENT_BRANCH_HACK(b) __asm__("" : "+r"(b));
#else
#  define PQCLEAN_PREVENT_BRANCH_HACK(b)
#endif
#endif
