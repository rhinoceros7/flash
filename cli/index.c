#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>

#include "flash/index.h"
#include "flash/errors.h"

#ifndef EX_USAGE
#define EX_USAGE 64
#endif

static void index_usage(void) {
  fprintf(stderr,
          "usage: flash index [options] <file.flsh>\n"
          "options:\n"
          "  --every=N       index every Nth frame (default: 16)\n"
          "  --rebuild       always rebuild the index even if it exists\n"
          "  --show          print a human-readable summary after building\n"
          "  --json          print a JSON summary after building\n"
          "                  (implies --show semantics)\n");
}

/* Small helper to parse --every=N into uint32_t */
static int parse_u32(const char* s, uint32_t* out) {
  if (!s || !*s) return -1;
  char* end = NULL;
  unsigned long long v = strtoull(s, &end, 10);
  if (end == s || *end != '\0') return -1;
  if (v == 0 || v > 0xffffffffULL) return -1;
  *out = (uint32_t)v;
  return 0;
}

/* Helper mirroring index.c to compute the .fidx path. */
static char* make_index_path_for_cli(const char* flsh_path) {
  size_t len = strlen(flsh_path);
  size_t cap = len + 6; /* ".fidx" + NUL */
  char* out = (char*)malloc(cap);
  if (!out) return NULL;
  memcpy(out, flsh_path, len);
  out[len] = '\0';
  char* dot = strrchr(out, '.');
  if (dot && strcmp(dot, ".flsh") == 0) {
    strcpy(dot, ".fidx");
  } else {
    strcpy(out + len, ".fidx");
  }
  return out;
}

static void print_summary(const char* flsh_path,
                          const char* fidx_path,
                          const flash_index* idx,
                          int is_stale,
                          int as_json) {
  const flash_index_header_v1* h = &idx->hdr;

  int64_t span_ns = 0;
  double  span_sec = 0.0;

  if (h->last_ts > h->first_ts) {
    span_ns  = h->last_ts - h->first_ts;
    span_sec = (double)span_ns / 1e9;
  }

  if (!as_json) {
    fprintf(stderr,
            "flash index: %s\n"
            "  index file : %s%s\n"
            "  entries    : %" PRIu64 "\n"
            "  every_n    : %" PRIu32 "\n"
            "  time range : %" PRId64 " .. %" PRId64
            " (ns, span ~%.6f s)\n"
            "  flsh size  : %" PRIu64 " bytes%s\n",
            flsh_path,
            fidx_path ? fidx_path : "(auto)",
            is_stale ? " (outdated vs .flsh)" : "",
            (uint64_t)h->entry_count,
            (uint32_t)h->every_n,
            (int64_t)h->first_ts,
            (int64_t)h->last_ts,
            span_sec,
            (uint64_t)h->flsh_size_bytes,
            is_stale ? " (size mismatch)" : "");
  } else {
    printf("{\"flsh_path\":\"%s\","
           "\"fidx_path\":\"%s\","
           "\"entries\":%" PRIu64 ","
           "\"every_n\":%" PRIu32 ","
           "\"first_ts\":%" PRId64 ","
           "\"last_ts\":%" PRId64 ","
           "\"span_ns\":%" PRId64 ","
           "\"flsh_size_bytes\":%" PRIu64 ","
           "\"outdated\":%s}\n",
           flsh_path,
           fidx_path ? fidx_path : "",
           (uint64_t)h->entry_count,
           (uint32_t)h->every_n,
           (int64_t)h->first_ts,
           (int64_t)h->last_ts,
           (int64_t)span_ns,
           (uint64_t)h->flsh_size_bytes,
           is_stale ? "true" : "false");
  }
}

/* Main command implementation, called from flash_main.c */
int cmd_index(int argc, char** argv) {
  const char* flsh_path = NULL;
  char* fidx_path_heap = NULL;
  const char* fidx_path = NULL;
  uint32_t every_n = 16;
  int have_every = 0;
  int want_rebuild = 0;
  int want_show = 0;
  int want_json = 0;

  /* argv[0] is "index"; parse flags starting at argv[1]. */
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (arg[0] == '-') {
      if (!strcmp(arg, "--every") || !strncmp(arg, "--every=", 8)) {
        const char* val = NULL;
        if (strncmp(arg, "--every=", 8) == 0) {
          val = arg + 8;
        } else {
          if (i + 1 >= argc) {
            fprintf(stderr, "flash index: --every requires a value\n");
            index_usage();
            return EX_USAGE;
          }
          val = argv[++i];
        }
        if (parse_u32(val, &every_n) != 0) {
          fprintf(stderr, "flash index: invalid --every value: %s\n", val);
          index_usage();
          return EX_USAGE;
        }
        have_every = 1;
      } else if (!strcmp(arg, "--rebuild")) {
        want_rebuild = 1;
      } else if (!strcmp(arg, "--show")) {
        want_show = 1;
      } else if (!strcmp(arg, "--json")) {
        want_json = 1;
      } else {
        fprintf(stderr, "flash index: unknown option '%s'\n", arg);
        index_usage();
        return EX_USAGE;
      }
    } else {
      if (flsh_path) {
        fprintf(stderr, "flash index: multiple input paths provided\n");
        index_usage();
        return EX_USAGE;
      }
      flsh_path = arg;
    }
  }

  if (!flsh_path) {
    fprintf(stderr, "flash index: missing <file.flsh>\n");
    index_usage();
    return EX_USAGE;
  }

  fidx_path_heap = make_index_path_for_cli(flsh_path);
  if (!fidx_path_heap) {
    fprintf(stderr, "flash index: failed to allocate index path\n");
    return 2;
  }
  fidx_path = fidx_path_heap;

  /* Try to load existing index if not forced to rebuild. */
  flash_index idx;
  int is_stale = 0;
  int rc = 0;
  int have_existing = 0;

  if (!want_rebuild) {
    rc = flash_index_load(flsh_path, fidx_path, &idx, &is_stale);
    if (rc == FLASH_OK && !is_stale) {
      have_existing = 1;
    } else {
      flash_index_free(&idx);
    }
  }

  if (!have_existing) {
    uint32_t use_every = have_every ? every_n : 16;
    rc = flash_index_build(flsh_path, fidx_path, use_every);
    if (rc != FLASH_OK) {
      fprintf(stderr,
              "flash index: failed to build index for '%s' (rc=%d)\n",
              flsh_path, rc);
      free(fidx_path_heap);
      return 2;
    }
    /* Re-load to get a populated flash_index struct for --show / --json. */
    rc = flash_index_load(flsh_path, fidx_path, &idx, &is_stale);
    if (rc != FLASH_OK) {
      fprintf(stderr,
              "flash index: built index but failed to reload '%s' (rc=%d)\n",
              fidx_path, rc);
      free(fidx_path_heap);
      return 2;
    }
  }

  if (want_show || want_json) {
    print_summary(flsh_path, fidx_path, &idx, is_stale, want_json);
  }

  flash_index_free(&idx);
  free(fidx_path_heap);
  return 0;
}
