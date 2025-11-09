#ifndef FLASH_INGEST_H
#define FLASH_INGEST_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    const char* out_path; // required
    // Source (exactly one)
    enum {
        SRC_STDIN, SRC_FILE, SRC_DIR, SRC_TCP, SRC_UDP, SRC_SERIAL,
        SRC_HTTP, SRC_SSE, SRC_WS
    } src_kind;
    const char* src_detail; // e.g., "path", "host:port", "COM3@115200", or a URL

    // Format (required)
    enum { FMT_AUTO, FMT_LINES, FMT_NDJSON, FMT_JSON, FMT_CSV, FMT_LEN4, FMT_RAW } fmt;

    // Type label (optional; if NULL, infer from format)
    const char* type_label;

    // Rotation (any or none)
    uint64_t rotate_bytes; // 0 = off
    uint64_t rotate_seconds; // 0 = off
    uint64_t rotate_records; // 0 = off

    // Behavior
    bool strict; // decoder mismatch: fail vs. fallback->raw
} ingest_config;

int flash_ingest_run(const ingest_config* cfg);

#endif // FLASH_INGEST_H