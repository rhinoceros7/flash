// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#include <stdint.h>
#include <stddef.h>

static uint32_t table[256];
static int table_init = 0;

static void init_table(void) {
    uint32_t poly = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = c & 1 ? poly ^ c >> 1 : c >> 1;
        table[i] = c;
    }
    table_init = 1;
}

uint32_t frf_crc32(const void* data, size_t n) {
    if (!table_init) init_table();
    const unsigned char* p = (const unsigned char*)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++)
        c = table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}
