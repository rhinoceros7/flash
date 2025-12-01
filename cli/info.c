#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ingest.h"
#include "flash/reader.h"
#include "frf.h"
#include "flash/seal.h"

// FSIG detection, reused.
#define FLASH_FSIG_TRAILER_SIZE 200

static int info_get_seal_status(const char* path, int* sealed_out, int* salvage_out) {
    if (!sealed_out || !salvage_out) return -1;
    *sealed_out = 0;
    *salvage_out = 0;

    int seal_rc = flash_seal_verify(path);
    if (seal_rc == -2) {
        fprintf(stderr,
                "flash info: flash_seal_verify() failed to open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    /* Non-zero (but not -2) means FRF is fine but not sealed / no valid FSIG.
       We still allow info to continue; just report sealed=no. */
    if (seal_rc != 0) {
        *sealed_out = 0;
        *salvage_out = 0;
        return 0;
    }

    /* At this point, sealing + hash-chain has already been verified.
       We only need minimal metadata from the FSIG trailer (seal_mode). */

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr,
                "flash info: open failed while reading FSIG: %s\n",
                strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr,
                "flash info: fseek(SEEK_END) failed while reading FSIG\n");
        fclose(f);
        return -1;
    }

    long end_pos = ftell(f);
    if (end_pos < 0) {
        fprintf(stderr,
                "flash info: ftell() failed while reading FSIG\n");
        fclose(f);
        return -1;
    }

    if ((long)FLASH_FSIG_TRAILER_SIZE > end_pos) {
        fprintf(stderr,
                "flash info: file shorter than FSIG trailer size\n");
        fclose(f);
        return -1;
    }

    if (fseek(f, end_pos - (long)FLASH_FSIG_TRAILER_SIZE, SEEK_SET) != 0) {
        fprintf(stderr,
                "flash info: fseek() to FSIG trailer failed\n");
        fclose(f);
        return -1;
    }

    unsigned char tr[FLASH_FSIG_TRAILER_SIZE];
    size_t n = fread(tr, 1, sizeof(tr), f);
    fclose(f);
    if (n != sizeof(tr)) {
        fprintf(stderr,
                "flash info: fread() FSIG trailer failed\n");
        return -1;
    }

    /* Layout matches seal.c / verify.c:
       - seal_mode at offset 7 (u8)
       - records at offset 20 (u64 LE), etc.
       We only care about seal_mode here. */

    uint8_t seal_mode = tr[7];
    *sealed_out = 1;
    *salvage_out = (seal_mode == FLASH_SEAL_SALVAGE);

    return 0;
}

#define INFO_FSIG_SEARCH_WINDOW 4096

static uint32_t info_le32(const unsigned char* p) {
    return (uint32_t)p[0]
         | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16
         | (uint32_t)p[3] << 24;
}

static uint64_t info_le64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}

/* Find FSIG magic near EOF so we know where the FRF frames stop.
   has_fsig=1 and fsig_offset=byte offset of 'F' in "FSIG" if found.
   file_bytes is always filled with the total file size on success. */
int info_detect_fsig(const char* path,
                            int* has_fsig,
                            uint64_t* fsig_offset_out,
                            uint64_t* file_bytes_out) {
    *has_fsig = 0;
    *fsig_offset_out = 0;
    *file_bytes_out = 0;

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr,
                "flash info: cannot open '%s' for FSIG scan: %s\n",
                path, strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr,
                "flash info: fseek(SEEK_END) failed for '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0) {
        fprintf(stderr,
                "flash info: ftell() failed for '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    *file_bytes_out = (uint64_t)size;

    if (size < 4) {
        fclose(f);
        return 0; /* too small for "FSIG" */
    }

    long window = size < INFO_FSIG_SEARCH_WINDOW
                ? size
                : INFO_FSIG_SEARCH_WINDOW;

    if (fseek(f, size - window, SEEK_SET) != 0) {
        fprintf(stderr,
                "flash info: fseek() to tail failed for '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    unsigned char buf[INFO_FSIG_SEARCH_WINDOW];
    size_t n = fread(buf, 1, (size_t)window, f);
    fclose(f);
    if (n != (size_t)window) {
        /* Short read; just treat as unsealed FRF. */
        return 0;
    }

    for (long i = 0; i <= window - 4; ++i) {
        if (buf[i] == 'F' && buf[i + 1] == 'S' &&
            buf[i + 2] == 'I' && buf[i + 3] == 'G') {
            *has_fsig = 1;
            *fsig_offset_out = (uint64_t)(size - window + i);
            return 0;
        }
    }

    /* No FSIG magic found; treat as unsealed FRF. */
    return 0;
}

int cmd_info(int argc, char** argv) {
  (void)argc;
  const char* path = argv[1];

  /* Detect FSIG trailer (if any) and total file size */
  int has_fsig = 0;
  uint64_t fsig_offset = 0;
  uint64_t file_bytes = 0;
  if (info_detect_fsig(path, &has_fsig, &fsig_offset, &file_bytes) != 0) {
    /* Error already printed */
    return 2;
  }

  /* Open as FRF and read header */
  frf_handle_t h;
  int rc = frf_open(path, "rb", &h);
  if (rc != 0) {
    fprintf(stderr,
            "flash info: failed to open '%s' as FRF (rc=%d)\n",
            path, rc);
    return 2;
  }

  frf_file_header_t fh;
  rc = frf_read_and_verify_header(&h, &fh);
  if (rc == -2) {
    fprintf(stderr,
            "flash info: '%s' is not a Flash record file (bad magic)\n",
            path);
    frf_close(&h);
    return 2;
  } else if (rc != 0) {
    fprintf(stderr,
            "flash info: header read failed for '%s' (rc=%d)\n",
            path, rc);
    frf_close(&h);
    return 2;
  }

  uint64_t created_ns = fh.created_unix_ns;

  /* Scan records up to FSIG (if present) */
  uint64_t records = 0;
  uint64_t total_frame_bytes = 0;
  uint64_t first_ts = 0;
  uint64_t last_ts = 0;
  int have_ts = 0;

  uint64_t offset = FRF_FILE_HEADER_BYTES;
  if (has_fsig && fsig_offset < offset) {
    fprintf(stderr,
            "flash info: FSIG offset is before FRF data region in '%s'\n",
            path);
    frf_close(&h);
    return 2;
  }

  if (fseek(h.fp, FRF_FILE_HEADER_BYTES, SEEK_SET) != 0) {
    fprintf(stderr,
            "flash info: fseek() to first frame failed for '%s': %s\n",
            path, strerror(errno));
    frf_close(&h);
    return 2;
  }

  for (;;) {
    if (has_fsig && offset >= fsig_offset) {
      /* We've reached the FSIG trailer region; stop. */
      break;
    }

    unsigned char hdr_bytes[FRF_RECORD_HEADER_BYTES];
    size_t n = fread(hdr_bytes, 1, sizeof(hdr_bytes), h.fp);
    if (n == 0) {
      /* Clean EOF for unsealed files */
      break;
    }
    if (n != sizeof(hdr_bytes)) {
      fprintf(stderr,
              "flash info: truncated record header in '%s' at offset %" PRIu64 "\n",
              path, offset);
      frf_close(&h);
      return 2;
    }

    uint32_t payload_len = info_le32(hdr_bytes + 0);
    /* uint32_t type = info_le32(hdr_bytes + 4); */ (void)0;
    uint64_t ts_unix_ns = info_le64(hdr_bytes + 8);

    uint64_t frame_bytes =
        (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)payload_len;

    /* Ensure we don't skip into FSIG */
    if (has_fsig && offset + frame_bytes > fsig_offset) {
      fprintf(stderr,
              "flash info: record at offset %" PRIu64
              " overlaps FSIG trailer in '%s'\n",
              offset, path);
      frf_close(&h);
      return 2;
    }

    /* Skip payload + hash chain */
    if (fseek(h.fp, (long)(payload_len + FRF_CHAIN_BYTES), SEEK_CUR) != 0) {
      fprintf(stderr,
              "flash info: truncated payload/chain in '%s' at offset %" PRIu64 "\n",
              path, offset);
      frf_close(&h);
      return 2;
    }

    /* Update stats */
    if (!have_ts) {
      first_ts = ts_unix_ns;
      have_ts = 1;
    }
    last_ts = ts_unix_ns;

    records++;
    total_frame_bytes += frame_bytes;
    offset += frame_bytes;
  }

  frf_close(&h);

  /* Pretty-print summary */
  char first_buf[32];
  char last_buf[32];
  char avg_buf[32];

  if (have_ts) {
    snprintf(first_buf, sizeof(first_buf), "%" PRIu64, first_ts);
    snprintf(last_buf, sizeof(last_buf), "%" PRIu64, last_ts);
  } else {
    strcpy(first_buf, "n/a");
    strcpy(last_buf, "n/a");
  }

  if (records > 0) {
    uint64_t avg = total_frame_bytes / records;
    snprintf(avg_buf, sizeof(avg_buf), "%" PRIu64, avg);
  } else {
    strcpy(avg_buf, "n/a");
  }

    int sealed = 0;
    int salvage = 0;
    if (info_get_seal_status(path, &sealed, &salvage) != 0) {
        return 2; /* error already printed */
    }

    printf("created_ns=%" PRIu64
         " first_ts=%s last_ts=%s records=%" PRIu64
         " file_bytes=%" PRIu64 " avg_frame_bytes=%s"
         " sealed=%s salvage=%s endianness=little\n",
         created_ns, first_buf, last_buf,
         records, file_bytes, avg_buf,
         sealed ? "yes" : "no",
         salvage ? "yes" : "no");

  return 0;
}