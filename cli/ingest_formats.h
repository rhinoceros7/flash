#ifndef FLASH_INGEST_FORMATS_H
#define FLASH_INGEST_FORMATS_H

#include <stdint.h>
#include "ingest.h"
#include "ingest_source.h"

typedef struct ingest_decoder ingest_decoder;

typedef int (*decoder_init_fn)(ingest_decoder*, const ingest_config*, ingest_source*);
typedef int (*decoder_next_fn)(ingest_decoder*, uint8_t** payload, uint32_t* len, uint64_t* ts_ns);
typedef void (*decoder_close_fn)(ingest_decoder*);

typedef enum {
    DECODER_STATUS_OK = 0,
    DECODER_STATUS_EOF = 1,
    DECODER_STATUS_ERROR = -1,
    DECODER_STATUS_MISMATCH = -2
  } decoder_status;

typedef struct {
    const char* source; // "now" or "field"
    const char* field; // NULL if source=="now"
    const char* parsed; // "rfc3339" | "unix_ms" | "unix_ns" | "none"
} ingest_timestamp_policy;

struct ingest_decoder {
    decoder_init_fn init;
    decoder_next_fn next;
    decoder_close_fn close;
    void* state;
    ingest_source* source;
    const ingest_config* cfg;
    ingest_timestamp_policy ts_policy;
    int ts_policy_reported;
    uint8_t* pending_raw;
    uint32_t pending_raw_len;
    int resolved_fmt;  // final decoder choice (after AUTO sniff)
};

int make_decoder(const ingest_config* cfg, ingest_source* source, ingest_decoder* out);
void destroy_decoder(ingest_decoder* decoder);

#endif // FLASH_INGEST_FORMATS_H