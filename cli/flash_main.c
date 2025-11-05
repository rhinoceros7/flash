#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "flash/reader.h"
#include "frf.h"
#ifndef EX_USAGE
#define EX_USAGE 64
#endif

typedef int (*flash_cmd_fn)(int argc, char** argv);

typedef struct {
  const char* name;
  flash_cmd_fn fn;
} flash_command;

static void print_usage(void) {
  fprintf(stderr,
          "usage: flash <command> [args]\n"
          "commands: info verify repair index replay export ingest cat tail\n");
}

static const char* status_name(int code) {
  switch (code) {
    case FLASH_OK: return "ok";
    case FLASH_EOF: return "eof";
    case FLASH_EIO: return "io_error";
    case FLASH_EBADMAGIC: return "bad_magic";
    case FLASH_ETRUNC_HDR: return "truncated_header";
    case FLASH_ETRUNC_PAYLOAD: return "truncated_payload";
    case FLASH_EBUFSIZE: return "buffer_too_small";
    case FLASH_ECRC: return "crc_mismatch";
    case FLASH_ECHAIN: return "chain_mismatch";
    default: return "unknown";
  }
}

static int cmd_info(int argc, char** argv) {
  if (argc != 2) {
    print_usage();
    return EX_USAGE;
  }
  const char* path = argv[1];
  flash_reader* reader = NULL;
  int rc = flash_reader_open(path, &reader);
  if (rc != FLASH_OK) {
    fprintf(stderr, "flash info: failed to open '%s': %s\n", path, status_name(rc));
    return 2;
  }

  uint64_t created_ns = 0;
  rc = flash_reader_header_created_ns(reader, &created_ns);
  if (rc != FLASH_OK) {
    fprintf(stderr, "flash info: header read failed: %s\n", status_name(rc));
    flash_reader_close(reader);
    return 2;
  }

  uint64_t file_bytes = 0;
  rc = flash_reader_filesize(reader, &file_bytes);
  if (rc != FLASH_OK) {
    fprintf(stderr, "flash info: filesize failed: %s\n", status_name(rc));
    flash_reader_close(reader);
    return 2;
  }

  uint64_t records = 0;
  uint64_t total_frame_bytes = 0;
  uint64_t first_ts = 0;
  uint64_t last_ts = 0;
  int have_ts = 0;

  for (;;) {
    flash_frame_meta meta;
    uint32_t payload_len = 0;
    int step = flash_reader_next(reader, &meta, NULL, 0, &payload_len);

    if (step == FLASH_OK) {
      if (!have_ts) { first_ts = meta.ts_unix_ns; have_ts = 1; }
      last_ts = meta.ts_unix_ns;
      records++;
      total_frame_bytes += (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)payload_len;
      continue;
    }
    if (step == FLASH_EOF) break;

    fprintf(stderr,
      "flash info: error while reading '%s' at offset %" PRIu64 ": %s\n",
      path, meta.file_offset, status_name(step));
    flash_reader_close(reader);
    return 2;
  }

  flash_reader_close(reader);

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

  printf("created_ns=%" PRIu64 " first_ts=%s last_ts=%s records=%" PRIu64
         " file_bytes=%" PRIu64 " avg_frame_bytes=%s endianness=little\n",
         created_ns, first_buf, last_buf, records, file_bytes, avg_buf);
  return 0;
}

static int verify_loop(flash_reader* reader, uint64_t file_bytes) {
  uint64_t records_ok = 0;
  uint64_t next_offset = FRF_FILE_HEADER_BYTES;
  int error_code = FLASH_OK;
  uint64_t error_offset = 0;
  int trailing_partial = 0;

  for (;;) {
    flash_frame_meta meta;
    uint32_t payload_len = 0;
    int step = flash_reader_next(reader, &meta, NULL, 0, &payload_len);
    if (step == FLASH_OK) {
      records_ok += 1;
      next_offset = meta.file_offset + (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)payload_len;
      continue;
    }
    if (step == FLASH_EOF) {
      break;
    }
    error_code = step;
    error_offset = next_offset;
    if (step == FLASH_ETRUNC_HDR || step == FLASH_ETRUNC_PAYLOAD) {
      trailing_partial = 1;
    }
    break;
  }

  if (error_code == FLASH_OK) {
    printf("records_ok=%" PRIu64 " bytes_scanned=%" PRIu64 "\n",
           records_ok, file_bytes);
    return 0;
  }

  if (trailing_partial) {
    printf("records_ok=%" PRIu64 " bytes_scanned=%" PRIu64
           " error_offset=%" PRIu64 " error=%s note=trailing_partial\n",
           records_ok, file_bytes, error_offset, status_name(error_code));
    return 1;
  }

  printf("records_ok=%" PRIu64 " bytes_scanned=%" PRIu64
         " error_offset=%" PRIu64 " error=%s\n",
         records_ok, file_bytes, error_offset, status_name(error_code));
  return 2;
}

static int cmd_verify(int argc, char** argv) {
  if (argc != 2) {
    print_usage();
    return EX_USAGE;
  }
  const char* path = argv[1];
  flash_reader* reader = NULL;
  int rc = flash_reader_open(path, &reader);
  if (rc != FLASH_OK) {
    fprintf(stderr, "flash verify: failed to open '%s': %s\n", path, status_name(rc));
    return 2;
  }

  uint64_t file_bytes = 0;
  rc = flash_reader_filesize(reader, &file_bytes);
  if (rc != FLASH_OK) {
    fprintf(stderr, "flash verify: filesize failed: %s\n", status_name(rc));
    flash_reader_close(reader);
    return 2;
  }

  int exit_code = verify_loop(reader, file_bytes);
  flash_reader_close(reader);
  return exit_code;
}

static int cmd_stub(int argc, char** argv) {
  (void)argc;
  fprintf(stderr, "flash %s: not implemented yet\n", argv[0]);
  return EX_USAGE;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage();
    return EX_USAGE;
  }

  flash_command commands[] = {
      {"info", cmd_info},
      {"verify", cmd_verify},
      {"repair", cmd_stub},
      {"index", cmd_stub},
      {"replay", cmd_stub},
      {"export", cmd_stub},
      {"ingest", cmd_stub},
      {"cat", cmd_stub},
      {"tail", cmd_stub},
  };
  const size_t command_count = sizeof(commands) / sizeof(commands[0]);

  const char* sub = argv[1];
  for (size_t i = 0; i < command_count; ++i) {
    if (strcmp(sub, commands[i].name) == 0) {
      return commands[i].fn(argc - 1, argv + 1);
    }
  }

  print_usage();
  return EX_USAGE;
}