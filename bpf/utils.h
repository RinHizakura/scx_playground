#ifndef UTILS_H
#define UTILS_H

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

__attribute__((unused)) static size_t strlen(const char *str)
{
    size_t len;

    for (len = 0; str[len]; len++) {
    }

    return len;
}

#endif
