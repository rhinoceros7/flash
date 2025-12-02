// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#ifndef FLASH_INDEX_H
#define FLASH_INDEX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FLASH_INDEX_MAGIC "FIDXv001"
#define FLASH_INDEX_MAGIC_LEN 8
#define FLASH_INDEX_VERSION 1

typedef struct {
    uint64_t frame_index; /* 0-based frame number */
    uint64_t offset; /* byte offset of frame start in .flsh */
    int64_t first_ts; /* first record timestamp in this frame (ns) or 0 */
    uint32_t flags; /* frame type / flags */
    uint32_t reserved; /* reserved for future use */
} flash_index_entry_v1;

typedef struct {
    uint8_t magic[FLASH_INDEX_MAGIC_LEN]; /* "FIDXv001" */
    uint8_t version; /* = FLASH_INDEX_VERSION */
    uint8_t anchor_mode; /* 0 = none (v1) */
    uint16_t header_size; /* sizeof(flash_index_header_v1) */
    uint16_t entry_size; /* sizeof(flash_index_entry_v1) */
    uint16_t flags; /* bit0 = partial_index, others reserved */

    uint32_t every_n; /* we indexed every Nth frame */

    uint64_t entry_count; /* number of entries following the header */

    int64_t first_ts; /* earliest timestamp in file (ns), or 0 if unknown */
    int64_t last_ts; /* latest timestamp in file (ns), or 0 if unknown */

    uint64_t flsh_size_bytes; /* size of .flsh when index was built */

    uint8_t flsh_digest[32]; /* reserved for future FSIG integration, zero for now */
    uint8_t chain_tip[32]; /* reserved for future FSIG integration, zero for now */

    uint8_t  reserved[32]; /* reserved/padding to keep header extensible */
} flash_index_header_v1;

typedef struct {
    flash_index_header_v1 hdr;
    flash_index_entry_v1* entries; /* count = hdr.entry_count */
} flash_index;

/* Build (or rebuild) an index for the given .flsh path into the given .fidx path.
   every_n == 0 will be treated as 1.
   Returns 0 on success, non-zero on failure (I/O, parse, etc.). */
int flash_index_build(const char* flsh_path,
                      const char* fidx_path,
                      uint32_t every_n);

/* Load an existing index. On success, *out is filled and must be freed with
   flash_index_free(). If is_stale is non-NULL, it will be set to 1 if the
   .flsh size no longer matches the size recorded in the index header, else 0.
   Returns 0 on success, non-zero on failure (I/O, bad magic/version, etc.). */
int flash_index_load(const char* flsh_path,
                     const char* fidx_path,
                     flash_index* out,
                     int* is_stale);

/* Free the entries array inside a flash_index struct. Safe to call on a
   zero-initialized struct. */
void flash_index_free(flash_index* idx);

/* Look up the best entry for a given timestamp.
   Returns NULL if there are no entries.
   Otherwise returns the entry with the largest first_ts <= ts.
   If ts is earlier than the first entry, returns the first entry. */
const flash_index_entry_v1* flash_index_find_by_ts(const flash_index* idx,
                                                   int64_t ts);

/* Look up the best entry for a given frame index.
   Returns NULL if there are no entries.
   In v1 this is implemented as a simple division by every_n with clamping. */
const flash_index_entry_v1* flash_index_find_by_frame(const flash_index* idx,
                                                      uint64_t frame_index);

#ifdef __cplusplus
}
#endif

#endif /* FLASH_INDEX_H */
