// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#ifndef FLASH_READER_H
#define FLASH_READER_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "flash/errors.h"

typedef struct flash_reader flash_reader;

typedef struct {
    uint64_t file_offset;
    uint64_t ts_unix_ns;
    uint32_t type;
    uint32_t length;
    uint32_t crc32;
} flash_frame_meta;

int  flash_reader_open(const char* path, flash_reader** out);
void flash_reader_close(flash_reader* r);

int  flash_reader_next(
    flash_reader* r, flash_frame_meta* meta,
    void* payload_buf, uint32_t buf_cap,
    uint32_t* payload_len
    );

int  flash_reader_header_created_ns(flash_reader* r, uint64_t* out_created_ns);
int  flash_reader_filesize(flash_reader* r, uint64_t* out_bytes);

#endif // FLASH_READER_H