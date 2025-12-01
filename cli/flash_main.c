#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ingest.h"
#include "flash/reader.h"
#include "frf.h"
#include <error.h>
#include <stdint.h>

// Define version
#ifndef FLASH_VERSION
#define FLASH_VERSION "1.0.0"
#endif

#ifndef EX_USAGE
#define EX_USAGE 64
#endif

typedef int (*flash_cmd_fn)(int argc, char** argv);

int cmd_verify(int argc, char **argv); /* Implemented in verify.c */
int cmd_repair(int argc, char **argv); /* Implemented in repair.c */
int cmd_replay(int argc, char **argv); /* Implemented in replay.c */
int cmd_index(int argc, char **argv); /* Implemented in index.c */
int cmd_merge(int argc, char **argv); /* Implemented in merge.c */
int cmd_export(int argc, char **argv); /* Implemented in export.c */
int cmd_info(int argc, char **argv); /* Implemented in info.c */

typedef struct {
  const char* name;
  flash_cmd_fn fn;
} flash_command;

static void print_version_flag(void) {
  printf("flash version %s (FRF magic %s)\n", FLASH_VERSION, FRF_MAGIC);
}

static void print_usage(void) {
  fprintf(stderr,
          "usage: flash <command> [args]\n"
          "commands: info verify repair ingest index replay export merge\n"
          "         flash --version  show version info\n");
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
  *out = base * multiplier;
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

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage();
    return EX_USAGE;
  }

  if (strcmp(argv[1], "--version") == 0 ||
    strcmp(argv[1], "-V") == 0 ||
    strcmp(argv[1], "version") == 0) {
    print_version_flag();
    return 0;
    }

  flash_command commands[] = {
      {"info", cmd_info},
      {"verify", cmd_verify},
      {"repair", cmd_repair},
      {"ingest", cmd_ingest},
      {"replay", cmd_replay},
      {"index", cmd_index},
      {"merge", cmd_merge},
      {"export", cmd_export},
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