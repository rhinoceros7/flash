// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#include "flash/index.h"
#include "flash/reader.h"
#include "flash/errors.h"
#include "flash/seal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Little-endian helpers */
static void idx_u32_to_le(uint32_t v, unsigned char out[4]) {
    out[0] = (unsigned char)v;
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}

static void idx_u64_to_le(uint64_t v, unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) {
        out[i] = (unsigned char)(v >> (8 * i));
    }
}

static void idx_i64_to_le(int64_t v, unsigned char out[8]) {
    idx_u64_to_le((uint64_t)v, out);
}

static uint32_t idx_le_to_u32(const unsigned char in[4]) {
    return (uint32_t)in[0]
         | (uint32_t)in[1] << 8
         | (uint32_t)in[2] << 16
         | (uint32_t)in[3] << 24;
}

static uint64_t idx_le_to_u64(const unsigned char in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (uint64_t)in[i] << (8 * i);
    }
    return v;
}

static int64_t idx_le_to_i64(const unsigned char in[8]) {
    return (int64_t)idx_le_to_u64(in);
}

/* Build a temporary path for atomic-ish index writes */
static int make_tmp_path(const char* base, char* out, size_t out_cap) {
    size_t len = strlen(base);
    const char* suffix = ".tmp";
    size_t suffix_len = strlen(suffix);
    if (len + suffix_len + 1 > out_cap) {
        return -1;
    }
    memcpy(out, base, len);
    memcpy(out + len, suffix, suffix_len);
    out[len + suffix_len] = '\0';
    return 0;
}

/* Replace .flsh with .fidx, or append .fidx if there is no .flsh suffix.
   Caller owns the returned buffer and must free it. */
static char* make_index_path(const char* flsh_path) {
    size_t len = strlen(flsh_path);
    size_t cap = len + 6; /* ".fidx" + NUL */
    char* out = malloc(cap);
    if (!out) return NULL;
    memcpy(out, flsh_path, len);
    out[len] = '\0';

    char* dot = strrchr(out, '.');
    if (dot && strcmp(dot, ".flsh") == 0) {
        strcpy(dot, ".fidx");
    } else {
        strcpy(out + len, ".fidx");
    }
    return out;
}

void flash_index_free(flash_index* idx) {
    if (!idx) return;
    free(idx->entries);
    idx->entries = NULL;
    memset(&idx->hdr, 0, sizeof(idx->hdr));
}

/* Encode header into a fixed-size on-disk buffer (little-endian) */
static void encode_header(const flash_index_header_v1* h,
                          unsigned char* buf,
                          size_t buf_size) {
    (void)buf_size;

    memset(buf, 0, buf_size);
    memcpy(buf + 0, h->magic, FLASH_INDEX_MAGIC_LEN);
    buf[8]  = h->version;
    buf[9]  = h->anchor_mode;
    idx_u32_to_le(h->header_size, buf + 10);
    idx_u32_to_le(h->entry_size, buf + 14);
    idx_u32_to_le(h->flags, buf + 18);
    idx_u32_to_le(h->every_n, buf + 22);
    idx_u64_to_le(h->entry_count, buf + 26);
    idx_i64_to_le(h->first_ts, buf + 34);
    idx_i64_to_le(h->last_ts, buf + 42);
    idx_u64_to_le(h->flsh_size_bytes, buf + 50);
    memcpy(buf + 58, h->flsh_digest, 32);
    memcpy(buf + 90, h->chain_tip, 32);
    /* reserved 32 bytes at buf+122 (implicitly zeroed) */
}

/* Decode header from on-disk buffer */
static int decode_header(flash_index_header_v1* h,
                         const unsigned char* buf,
                         size_t buf_size) {
    (void)buf_size;
    memcpy(h->magic, buf + 0, FLASH_INDEX_MAGIC_LEN);
    h->version = buf[8];
    h->anchor_mode = buf[9];
    h->header_size = (uint16_t)idx_le_to_u32(buf + 10);
    h->entry_size  = (uint16_t)idx_le_to_u32(buf + 14);
    h->flags = (uint16_t)idx_le_to_u32(buf + 18);
    h->every_n = idx_le_to_u32(buf + 22);
    h->entry_count = idx_le_to_u64(buf + 26);
    h->first_ts = idx_le_to_i64(buf + 34);
    h->last_ts = idx_le_to_i64(buf + 42);
    h->flsh_size_bytes = idx_le_to_u64(buf + 50);
    memcpy(h->flsh_digest, buf + 58, 32);
    memcpy(h->chain_tip, buf + 90, 32);
    memset(h->reserved, 0, sizeof(h->reserved)); /* not stored yet */
    return 0;
}

/* Encode a single entry to 32 bytes */
static void encode_entry(const flash_index_entry_v1* e, unsigned char* buf32) {
    idx_u64_to_le(e->frame_index, buf32 + 0);
    idx_u64_to_le(e->offset, buf32 + 8);
    idx_i64_to_le(e->first_ts, buf32 + 16);
    idx_u32_to_le(e->flags, buf32 + 24);
    idx_u32_to_le(e->reserved, buf32 + 28);
}

/* Decode a single entry from 32 bytes */
static void decode_entry(flash_index_entry_v1* e, const unsigned char* buf32) {
    e->frame_index = idx_le_to_u64(buf32 + 0);
    e->offset = idx_le_to_u64(buf32 + 8);
    e->first_ts = idx_le_to_i64(buf32 + 16);
    e->flags = idx_le_to_u32(buf32 + 24);
    e->reserved = idx_le_to_u32(buf32 + 28);
}

int flash_index_build(const char* flsh_path,
                      const char* fidx_path_opt,
                      uint32_t every_n) {
    if (!flsh_path) {
        return FLASH_EIO;
    }
    if (every_n == 0) {
        every_n = 1;
    }

    int rc = FLASH_OK;
    int sealed_ok = 0;
    flash_reader* r = NULL;
    flash_frame_meta meta;
    uint32_t payload_len = 0;
    uint64_t flsh_size_bytes = 0;

    flash_index_entry_v1* entries = NULL;
    size_t entry_count = 0;
    size_t entry_cap = 0;

    int have_first_ts = 0;
    int64_t first_ts = 0;
    int64_t last_ts = 0;

    char* fidx_path_heap = NULL;
    const char* fidx_path = fidx_path_opt;

    if (!fidx_path) {
        fidx_path_heap = make_index_path(flsh_path);
        if (!fidx_path_heap) {
            return FLASH_EIO;
        }
        fidx_path = fidx_path_heap;
    }

    /* Check if file has a valid FSIG trailer. If so, we can treat
        truncation errors at the end as hitting the FSIG region. */
    {
        int seal_rc = flash_seal_verify(flsh_path);
        if (seal_rc == 0) {
            sealed_ok = 1;
        }
    }

    rc = flash_reader_open(flsh_path, &r);
    if (rc != FLASH_OK) {
        free(fidx_path_heap);
        return rc;
    }

    (void)flash_reader_filesize(r, &flsh_size_bytes);

    uint64_t frame_index = 0;

    for (;;) {
        int s = flash_reader_next(r, &meta, NULL, 0, &payload_len);
        if (s == FLASH_EOF) {
            rc = FLASH_OK;
            break;
        }
        if (s != FLASH_OK) {
            /* If the file is FSIG-verified, a truncation here most likely
               means we've walked into the FSIG trailer, not real FRF
               corruption. We treat that as a clean EOF. */
            if (sealed_ok && (s == FLASH_ETRUNC_HDR || s == FLASH_ETRUNC_PAYLOAD)) {
                rc = FLASH_OK;
                break;
            }
            rc = s;
            break;
        }

        int64_t ts = (int64_t)meta.ts_unix_ns;
        if (ts != 0) {
            if (!have_first_ts) {
                first_ts = ts;
                have_first_ts = 1;
            }
            last_ts = ts;
        }

        if (frame_index % every_n == 0) {
            if (entry_count == entry_cap) {
                size_t new_cap = entry_cap ? entry_cap * 2 : 1024;
                flash_index_entry_v1* tmp =
                    realloc(entries, new_cap * sizeof(flash_index_entry_v1));
                if (!tmp) {
                    rc = FLASH_EIO;
                    break;
                }
                entries = tmp;
                entry_cap = new_cap;
            }
            flash_index_entry_v1* e = &entries[entry_count++];
            e->frame_index = frame_index;
            e->offset = meta.file_offset;
            e->first_ts = ts;
            e->flags = meta.type;
            e->reserved = 0;
        }

        frame_index++;
    }

    flash_reader_close(r);
    r = NULL;

    if (rc != FLASH_OK) {
        free(entries);
        free(fidx_path_heap);
        return rc;
    }

    flash_index_header_v1 hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, FLASH_INDEX_MAGIC, FLASH_INDEX_MAGIC_LEN);
    hdr.version = FLASH_INDEX_VERSION;
    hdr.anchor_mode = 0;
    hdr.header_size = sizeof(flash_index_header_v1);
    hdr.entry_size  = sizeof(flash_index_entry_v1);
    hdr.flags = 0;
    hdr.every_n = every_n;
    hdr.entry_count = entry_count;
    hdr.first_ts = have_first_ts ? first_ts : 0;
    hdr.last_ts  = have_first_ts ? last_ts  : 0;
    hdr.flsh_size_bytes = flsh_size_bytes;
    /* flsh_digest / chain_tip left zero for now */

    unsigned char header_buf[128];
    encode_header(&hdr, header_buf, sizeof(header_buf));

    char tmp_path[PATH_MAX];
    if (make_tmp_path(fidx_path, tmp_path, sizeof(tmp_path)) != 0) {
        free(entries);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    FILE* f = fopen(tmp_path, "wb");
    if (!f) {
        free(entries);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    size_t written = fwrite(header_buf, 1, sizeof(header_buf), f);
    if (written != sizeof(header_buf)) {
        fclose(f);
        remove(tmp_path);
        free(entries);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    unsigned char entry_buf[32];
    for (size_t i = 0; i < entry_count; ++i) {
        encode_entry(&entries[i], entry_buf);
        written = fwrite(entry_buf, 1, sizeof(entry_buf), f);
        if (written != sizeof(entry_buf)) {
            fclose(f);
            remove(tmp_path);
            free(entries);
            free(fidx_path_heap);
            return FLASH_EIO;
        }
    }

    if (fflush(f) != 0) {
        fclose(f);
        remove(tmp_path);
        free(entries);
        free(fidx_path_heap);
        return FLASH_EIO;
    }
    if (fclose(f) != 0) {
        remove(tmp_path);
        free(entries);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    /* Replace any existing index file */
    remove(fidx_path);
    if (rename(tmp_path, fidx_path) != 0) {
        remove(tmp_path);
        free(entries);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    free(entries);
    free(fidx_path_heap);
    return FLASH_OK;
}

int flash_index_load(const char* flsh_path,
                     const char* fidx_path_opt,
                     flash_index* out,
                     int* is_stale) {
    if (!out || !flsh_path) {
        return FLASH_EIO;
    }
    memset(out, 0, sizeof(*out));
    if (is_stale) {
        *is_stale = 0;
    }

    char* fidx_path_heap = NULL;
    const char* fidx_path = fidx_path_opt;
    if (!fidx_path) {
        fidx_path_heap = make_index_path(flsh_path);
        if (!fidx_path_heap) {
            return FLASH_EIO;
        }
        fidx_path = fidx_path_heap;
    }

    FILE* f = fopen(fidx_path, "rb");
    if (!f) {
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    unsigned char header_buf[128];
    size_t n = fread(header_buf, 1, sizeof(header_buf), f);
    if (n != sizeof(header_buf)) {
        fclose(f);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    flash_index_header_v1 hdr;
    decode_header(&hdr, header_buf, sizeof(header_buf));

    if (memcmp(hdr.magic, FLASH_INDEX_MAGIC, FLASH_INDEX_MAGIC_LEN) != 0) {
        fclose(f);
        free(fidx_path_heap);
        return FLASH_EBADMAGIC;
    }
    if (hdr.version != FLASH_INDEX_VERSION) {
        fclose(f);
        free(fidx_path_heap);
        return FLASH_EBADMAGIC;
    }
    if (hdr.entry_size != sizeof(flash_index_entry_v1)) {
        fclose(f);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    if (hdr.entry_count > (UINT64_C(1) << 40)) { /* sanity cap */
        fclose(f);
        free(fidx_path_heap);
        return FLASH_EIO;
    }

    size_t count = hdr.entry_count;
    flash_index_entry_v1* entries = NULL;
    if (count > 0) {
        entries = (flash_index_entry_v1*)malloc(count * sizeof(flash_index_entry_v1));
        if (!entries) {
            fclose(f);
            free(fidx_path_heap);
            return FLASH_EIO;
        }
        unsigned char entry_buf[32];
        for (size_t i = 0; i < count; ++i) {
            n = fread(entry_buf, 1, sizeof(entry_buf), f);
            if (n != sizeof(entry_buf)) {
                free(entries);
                fclose(f);
                free(fidx_path_heap);
                return FLASH_EIO;
            }
            decode_entry(&entries[i], entry_buf);
        }
    }

    fclose(f);

    /* Check staleness by comparing .flsh size */
    if (is_stale) {
        *is_stale = 0;
        flash_reader* r = NULL;
        uint64_t size_now = 0;
        int rc = flash_reader_open(flsh_path, &r);
        if (rc == FLASH_OK) {
            (void)flash_reader_filesize(r, &size_now);
            flash_reader_close(r);
            if (size_now != hdr.flsh_size_bytes) {
                *is_stale = 1;
            }
        } else {
            /* If we cannot even open the .flsh, treat as stale but not fatal here. */
            *is_stale = 1;
        }
    }

    out->hdr = hdr;
    out->entries = entries;

    free(fidx_path_heap);
    return FLASH_OK;
}

const flash_index_entry_v1* flash_index_find_by_ts(const flash_index* idx,
                                                   int64_t ts) {
    if (!idx || !idx->entries || idx->hdr.entry_count == 0) {
        return NULL;
    }

    size_t lo = 0;
    size_t hi = idx->hdr.entry_count;
    /* Find first entry with first_ts > ts */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int64_t mid_ts = idx->entries[mid].first_ts;
        if (mid_ts > ts) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    if (lo == 0) {
        return &idx->entries[0];
    }
    return &idx->entries[lo - 1];
}

const flash_index_entry_v1* flash_index_find_by_frame(const flash_index* idx,
                                                      uint64_t frame_index) {
    if (!idx || !idx->entries || idx->hdr.entry_count == 0) {
        return NULL;
    }
    uint32_t every_n = idx->hdr.every_n ? idx->hdr.every_n : 1;
    uint64_t approx = frame_index / every_n;
    size_t count = idx->hdr.entry_count;
    if (approx >= count) {
        approx = count - 1;
    }
    return &idx->entries[approx];
}
