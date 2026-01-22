// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#ifndef FLASH_OFFSET_H
#define FLASH_OFFSET_H

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>

#if !defined(_WIN32)
#include <sys/types.h>
#endif

typedef uint64_t flsh_off_t;
#define FLSH_PRIuOFF PRIu64

static inline int flsh_add_overflow(flsh_off_t a, flsh_off_t b, flsh_off_t* out) {
    if (b > UINT64_MAX - a) {
        return 1;
    }
    if (out) {
        *out = a + b;
    }
    return 0;
}

static inline int flsh_seek(FILE* fp, flsh_off_t offset, int whence) {
#if defined(_WIN32)
    if (offset > (flsh_off_t)LLONG_MAX) {
        return -1;
    }
    return _fseeki64(fp, (long long)offset, whence);
#else
    if (offset > (flsh_off_t)LLONG_MAX) {
        return -1;
    }
    return fseeko(fp, (off_t)offset, whence);
#endif
}

static inline int flsh_tell(FILE* fp, flsh_off_t* out) {
#if defined(_WIN32)
    long long pos = _ftelli64(fp);
    if (pos < 0) {
        return -1;
    }
    if (out) {
        *out = (flsh_off_t)pos;
    }
    return 0;
#else
    off_t pos = ftello(fp);
    if (pos < 0) {
        return -1;
    }
    if (out) {
        *out = (flsh_off_t)pos;
    }
    return 0;
#endif
}

static inline int flsh_file_size(FILE* fp, flsh_off_t* out) {
    flsh_off_t cur = 0;
    flsh_off_t end = 0;
    if (flsh_tell(fp, &cur) != 0) {
        return -1;
    }
    if (flsh_seek(fp, 0, SEEK_END) != 0) {
        return -1;
    }
    if (flsh_tell(fp, &end) != 0) {
        return -1;
    }
    if (flsh_seek(fp, cur, SEEK_SET) != 0) {
        return -1;
    }
    if (out) {
        *out = end;
    }
    return 0;
}

static inline int flsh_range_valid(flsh_off_t offset,
                                   flsh_off_t length,
                                   flsh_off_t file_size) {
    flsh_off_t end = 0;
    if (flsh_add_overflow(offset, length, &end) != 0) {
        return 0;
    }
    return end <= file_size;
}

#endif /* FLASH_OFFSET_H */
