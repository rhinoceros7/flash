// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif
#include "flash/reader.h"
#include "frf.h"
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/types.h>
#endif

struct flash_reader {
  frf_handle_t handle;
  uint64_t created_ns;
  bool header_cached;
  uint64_t current_offset; // start of next record header
  unsigned char* scratch;
  uint32_t scratch_cap;
};

static int ensure_scratch(flash_reader* r, uint32_t need) {
  if (need == 0) need = 1;
  if (r->scratch_cap >= need && r->scratch) {
    return FLASH_OK;
  }
  uint32_t new_cap = r->scratch_cap ? r->scratch_cap : 4096u;
  while (new_cap < need) {
    if (new_cap > UINT32_MAX / 2) {
      new_cap = need;
      break;
    }
    new_cap *= 2;
  }
  unsigned char* new_buf = (unsigned char*)realloc(r->scratch, new_cap);
  if (!new_buf) {
    return FLASH_EIO;
  }
  r->scratch = new_buf;
  r->scratch_cap = new_cap;
  return FLASH_OK;
}

static int flash_seek(FILE* fp, uint64_t offset) {
#if defined(_WIN32)
  return _fseeki64(fp, (long long)offset, SEEK_SET);
#else
  return fseeko(fp, (off_t)offset, SEEK_SET);
#endif
}

static int flash_tell(FILE* fp, uint64_t* out) {
#if defined(_WIN32)
  long long pos = _ftelli64(fp);
  if (pos < 0) return -1;
  *out = (uint64_t)pos;
  return 0;
#else
  off_t pos = ftello(fp);
  if (pos < 0) return -1;
  *out = (uint64_t)pos;
  return 0;
#endif
}

int flash_reader_open(const char* path, flash_reader** out) {
  if (!path || !out) {
    return FLASH_EIO;
  }
  flash_reader* r = (flash_reader*)calloc(1, sizeof(*r));
  if (!r) {
    return FLASH_EIO;
  }
  if (frf_open(path, "rb", &r->handle) != 0) {
    free(r);
    return FLASH_EIO;
  }

  frf_file_header_t header;
  int rc = frf_read_and_verify_header(&r->handle, &header);
  if (rc != 0) {
    frf_close(&r->handle);
    free(r);
    if (rc == -2) {
      return FLASH_EBADMAGIC;
    }
    return FLASH_EIO;
  }

  r->created_ns = header.created_unix_ns;
  r->header_cached = true;
  r->current_offset = FRF_FILE_HEADER_BYTES;
  r->scratch = NULL;
  r->scratch_cap = 0;
  *out = r;
  return FLASH_OK;
}

void flash_reader_close(flash_reader* r) {
  if (!r) return;
  if (r->handle.fp) {
    frf_close(&r->handle);
  }
  free(r->scratch);
  free(r);
}

int flash_reader_header_created_ns(flash_reader* r, uint64_t* out_created_ns) {
  if (!r || !out_created_ns) {
    return FLASH_EIO;
  }
  if (!r->header_cached) {
    return FLASH_EIO;
  }
  *out_created_ns = r->created_ns;
  return FLASH_OK;
}

int flash_reader_filesize(flash_reader* r, uint64_t* out_bytes) {
  if (!r || !out_bytes || !r->handle.fp) {
    return FLASH_EIO;
  }
  FILE* fp = r->handle.fp;
  uint64_t cur;
  if (flash_tell(fp, &cur) != 0) {
    return FLASH_EIO;
  }
#if defined(_WIN32)
  if (_fseeki64(fp, 0, SEEK_END) != 0) {
    return FLASH_EIO;
  }
  long long end = _ftelli64(fp);
  if (end < 0) {
    return FLASH_EIO;
  }
  if (_fseeki64(fp, (long long)cur, SEEK_SET) != 0) {
    return FLASH_EIO;
  }
#else
  if (fseeko(fp, 0, SEEK_END) != 0) {
    return FLASH_EIO;
  }
  off_t end = ftello(fp);
  if (end < 0) {
    return FLASH_EIO;
  }
  if (fseeko(fp, (off_t)cur, SEEK_SET) != 0) {
    return FLASH_EIO;
  }
#endif
  *out_bytes = (uint64_t)end;
  return FLASH_OK;
}

int flash_reader_next(flash_reader* r,
                      flash_frame_meta* meta,
                      void* payload_buf,
                      uint32_t buf_cap,
                      uint32_t* payload_len) {
  if (!r || !meta) {
    return FLASH_EIO;
  }
  FILE* fp = r->handle.fp;
  if (!fp) {
    return FLASH_EIO;
  }

  uint64_t offset = r->current_offset;
  frf_record_header_t hdr;
  uint32_t read_len = 0;

retry:
  if (ensure_scratch(r, 1) != FLASH_OK) {
    return FLASH_EIO;
  }
  int rc = frf_next_record(&r->handle, &hdr, r->scratch, r->scratch_cap, &read_len);
  if (rc == -3 && hdr.length > r->scratch_cap) {
    if (ensure_scratch(r, hdr.length) != FLASH_OK) {
      return FLASH_EIO;
    }
    if (flash_seek(fp, offset) != 0) {
      return FLASH_EIO;
    }
    goto retry;
  }

  switch (rc) {
    case 0:
      break;
    case 1:
      if (payload_len) *payload_len = 0;
      return FLASH_EOF;
    case -2:
      return FLASH_ETRUNC_HDR;
    case -4:
      return FLASH_ETRUNC_PAYLOAD;
    case -6:
      return FLASH_ECRC;
    case -7:
      return FLASH_ECHAIN;
    default:
      return FLASH_EIO;
  }

  meta->file_offset = offset;
  meta->length = hdr.length;
  meta->type = hdr.type;
  meta->ts_unix_ns = hdr.ts_unix_ns;
  meta->crc32 = hdr.crc32;
  if (payload_len) {
    *payload_len = hdr.length;
  }

  if (payload_buf) {
    if (buf_cap < hdr.length) {
      r->current_offset = offset + (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)hdr.length;
      return FLASH_EBUFSIZE;
    }
    if (hdr.length > 0) {
      memcpy(payload_buf, r->scratch, hdr.length);
    }
  }

  r->current_offset = offset + (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)hdr.length;
  return FLASH_OK;
}