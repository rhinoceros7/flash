#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ingest.h"
#include "flash/reader.h"
#include "frf.h"
#include "ingest_source.h"
#include "ingest_formats.h"

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

static int strings_equal_ci(const char* a, const char* b) {
  return strcasecmp(a, b) == 0;
}

static void trim_in_place(char* s) {
  if (!s) return;
  char* start = s;
  while (*start && isspace((unsigned char)*start)) start++;
  if (start != s) {
    memmove(s, start, strlen(start) + 1);
  }
  size_t len = strlen(s);
  while (len > 0 && isspace((unsigned char)s[len - 1])) {
    s[len - 1] = '\0';
    --len;
  }
}

static int parse_size_value(const char* text, uint64_t* out) {
  if (strings_equal_ci(text, "off") || strings_equal_ci(text, "0")) {
    *out = 0;
    return 0;
  }
  char* end = NULL;
  unsigned long long base = strtoull(text, &end, 10);
  if (end == text) return -1;
  uint64_t multiplier = 1;
  if (*end) {
    if (end[1] != '\0') return -1;
    switch (tolower((unsigned char)*end)) {
      case 'k': multiplier = 1024ULL; break;
      case 'm': multiplier = 1024ULL * 1024ULL; break;
      case 'g': multiplier = 1024ULL * 1024ULL * 1024ULL; break;
      default: return -1;
    }
  }
  if (multiplier != 0 && base > UINT64_MAX / multiplier) return -1;
  *out = (uint64_t)base * multiplier;
  return 0;
}

static int parse_time_value(const char* text, uint64_t* out) {
  if (strings_equal_ci(text, "off") || strings_equal_ci(text, "0")) {
    *out = 0;
    return 0;
  }
  char* end = NULL;
  unsigned long long base = strtoull(text, &end, 10);
  if (end == text) return -1;
  uint64_t multiplier = 1;
  if (*end) {
    if (end[1] != '\0') return -1;
    switch (tolower((unsigned char)*end)) {
      case 'h': multiplier = 3600ULL; break;
      case 'm': multiplier = 60ULL; break;
      case 's': multiplier = 1ULL; break;
      default: return -1;
    }
  }
  if (multiplier != 0 && base > UINT64_MAX / multiplier) return -1;
  *out = (uint64_t)base * multiplier;
  return 0;
}

static int parse_record_value(const char* text, uint64_t* out) {
  if (strings_equal_ci(text, "off") || strings_equal_ci(text, "0")) {
    *out = 0;
    return 0;
  }
  char* end = NULL;
  unsigned long long base = strtoull(text, &end, 10);
  if (end == text) return -1;
  uint64_t multiplier = 1;
  if (*end) {
    if (end[1] != '\0') return -1;
    switch (tolower((unsigned char)*end)) {
      case 'k': multiplier = 1000ULL; break;
      case 'm': multiplier = 1000000ULL; break;
      default: return -1;
    }
  }
  if (multiplier != 0 && base > UINT64_MAX / multiplier) return -1;
  *out = (uint64_t)base * multiplier;
  return 0;
}

static int parse_rotate_clause(const char* arg, ingest_config* cfg) {
  if (strings_equal_ci(arg, "off") || strings_equal_ci(arg, "none")) {
    cfg->rotate_bytes = 0;
    cfg->rotate_seconds = 0;
    cfg->rotate_records = 0;
    return 0;
  }
  size_t len = strlen(arg);
  if (len >= 256) return -1;
  char buf[256];
  memcpy(buf, arg, len + 1);
  char* cursor = buf;
  int found = 0;
  while (*cursor) {
    char* part = cursor;
    char* comma = strchr(part, ',');
    if (comma) {
      *comma = '\0';
      cursor = comma + 1;
    } else {
      cursor = part + strlen(part);
    }
    trim_in_place(part);
    if (*part == '\0') continue;
    const char* key = "records";
    char* value = part;
    char* eq = strchr(part, '=');
    if (eq) {
      *eq = '\0';
      trim_in_place(part);
      trim_in_place(eq + 1);
      key = part;
      value = eq + 1;
    }
    uint64_t parsed = 0;
    if (strings_equal_ci(key, "size")) {
      if (parse_size_value(value, &parsed) != 0) return -1;
      cfg->rotate_bytes = parsed;
    } else if (strings_equal_ci(key, "time")) {
      if (parse_time_value(value, &parsed) != 0) return -1;
      cfg->rotate_seconds = parsed;
    } else if (strings_equal_ci(key, "records") || strings_equal_ci(key, "recs")) {
      if (parse_record_value(value, &parsed) != 0) return -1;
      cfg->rotate_records = parsed;
    } else {
      return -1;
    }
    found = 1;
  }
  return found ? 0 : -1;
}

static int parse_format_token(const char* tok, int* out_fmt) {
  if (strings_equal_ci(tok, "auto")) { *out_fmt = FMT_AUTO;  return 0; }
  if (strings_equal_ci(tok, "lines")) { *out_fmt = FMT_LINES; return 0; }
  if (strings_equal_ci(tok, "ndjson") ||
      strings_equal_ci(tok, "lines+json")) { *out_fmt = FMT_NDJSON; return 0; }
  if (strings_equal_ci(tok, "json")) { *out_fmt = FMT_JSON;  return 0; }
  if (strings_equal_ci(tok, "csv")) { *out_fmt = FMT_CSV;   return 0; }
  if (strings_equal_ci(tok, "len4")) { *out_fmt = FMT_LEN4;  return 0; }
  if (strings_equal_ci(tok, "raw")) { *out_fmt = FMT_RAW;   return 0; }
  return -1;
}

static int parse_source_clause(int argc, char** argv, int* idx, ingest_config* cfg) {
  if (*idx >= argc) return -1;
  const char* kind = argv[(*idx)++];

  if (strings_equal_ci(kind, "stdin")) {
    cfg->src_kind = SRC_STDIN;
    cfg->src_detail = NULL;
    return 0;
  }

  if (*idx >= argc) return -1;
  const char* detail = argv[(*idx)++];

  if (strings_equal_ci(kind, "file")) { cfg->src_kind = SRC_FILE; cfg->src_detail = detail; return 0; }
  if (strings_equal_ci(kind, "dir")) { cfg->src_kind = SRC_DIR; cfg->src_detail = detail; return 0; }
  if (strings_equal_ci(kind, "tcp")) { cfg->src_kind = SRC_TCP; cfg->src_detail = detail; return 0; }
  if (strings_equal_ci(kind, "udp")) { cfg->src_kind = SRC_UDP; cfg->src_detail = detail; return 0; }
  if (strings_equal_ci(kind, "serial")) { cfg->src_kind = SRC_SERIAL; cfg->src_detail = detail; return 0; }

  // URL-like sources
  if (strings_equal_ci(kind, "http")) { cfg->src_kind = SRC_HTTP; cfg->src_detail = detail; return 0; }
  if (strings_equal_ci(kind, "sse")) { cfg->src_kind = SRC_SSE; cfg->src_detail = detail; return 0; }
  if (strings_equal_ci(kind, "ws")) { cfg->src_kind = SRC_WS; cfg->src_detail = detail; return 0; }

  return -1;
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

static int cmd_ingest(int argc, char** argv) {
  if (argc < 6) { print_usage(); return EX_USAGE; }

  ingest_config cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.out_path = argv[1];

  int idx = 2;
  if (idx >= argc || !strings_equal_ci(argv[idx], "from")) { print_usage(); return EX_USAGE; }
  idx += 1;

  if (parse_source_clause(argc, argv, &idx, &cfg) != 0) {
    fprintf(stderr, "flash ingest: invalid source specification\n");
    return EX_USAGE;
  }

  if (idx >= argc || !strings_equal_ci(argv[idx], "as")) { print_usage(); return EX_USAGE; }
  idx += 1;

  if (idx >= argc || parse_format_token(argv[idx], (int*)&cfg.fmt) != 0) {
    fprintf(stderr, "flash ingest: unknown format\n");
    return EX_USAGE;
  }
  idx += 1;

  cfg.type_label = NULL;
  cfg.rotate_bytes = 0;
  cfg.rotate_seconds = 0;
  cfg.rotate_records = 0;
  cfg.strict = false;

  while (idx < argc) {
    const char* tok = argv[idx++];
    if (strings_equal_ci(tok, "type")) {
      if (idx >= argc) { fprintf(stderr, "flash ingest: missing type label\n"); return EX_USAGE; }
      cfg.type_label = argv[idx++];
    } else if (strings_equal_ci(tok, "rotate")) {
      if (idx >= argc) { fprintf(stderr, "flash ingest: missing rotate clause\n"); return EX_USAGE; }
      if (parse_rotate_clause(argv[idx++], &cfg) != 0) {
        fprintf(stderr, "flash ingest: invalid rotate clause\n");
        return EX_USAGE;
      }
    } else if (strings_equal_ci(tok, "strict")) {
      cfg.strict = true;
    } else {
      fprintf(stderr, "flash ingest: unknown option '%s'\n", tok);
      return EX_USAGE;
    }
  }

  return flash_ingest_run(&cfg);
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
      {"ingest", cmd_ingest},
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