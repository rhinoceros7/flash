#ifndef FLASH_INGEST_SOURCE_H
#define FLASH_INGEST_SOURCE_H
#include <stddef.h>
#include <stdint.h>

#include "ingest.h"

typedef struct ingest_source ingest_source;

typedef enum {
    SOURCE_STATUS_OK = 0,
    SOURCE_STATUS_EOF = 1,
    SOURCE_STATUS_ERROR = -1
  } source_status;

struct ingest_source;

int ingest_source_open(const ingest_config* cfg, ingest_source** out_source, char* err_msg, size_t err_cap);
int ingest_source_read(ingest_source* src, uint8_t* buf, size_t cap, size_t* out_bytes);
int ingest_source_getc(ingest_source* src, int* out_ch);
int ingest_source_unread(ingest_source* src, const uint8_t* data, size_t len);
const char* ingest_source_current_detail(ingest_source* src);
int ingest_source_close(ingest_source* src);

#endif // FLASH_INGEST_SOURCE_H