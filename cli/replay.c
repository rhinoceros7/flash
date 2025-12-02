// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include "frf.h"
#include "flash/index.h"

#ifndef EX_USAGE
#define EX_USAGE 64
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// timestamp parsing helpers
static int parse_u64(const char* s, uint64_t* out) {
  if (!s || !*s) return -1;
  char* end = NULL;
  errno = 0;
  unsigned long long v = strtoull(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0') return -1;
  *out = v;
  return 0;
}

#if defined(_WIN32)
static time_t timegm_compat(struct tm* t) {
  return _mkgmtime(t);
}
#else
static time_t timegm_compat(struct tm* t) {
  return timegm(t);
}
#endif

// Accepts "YYYY-MM-DDTHH:MM:SS" with optional ".fffffffff" and optional 'Z'.
// Example: 2025-11-17T12:23:45.123456789Z
static int parse_iso8601_ns(const char* s, uint64_t* out_ns) {
  if (!s) return -1;
  if (strlen(s) < 19) return -1;

  int year = 0, mon = 0, day = 0, hh = 0, mm = 0, ss = 0;
  if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d",
             &year, &mon, &day, &hh, &mm, &ss) != 6) {
    return -1;
  }

  struct tm tmv;
  memset(&tmv, 0, sizeof(tmv));
  tmv.tm_year = year - 1900;
  tmv.tm_mon = mon - 1;
  tmv.tm_mday = day;
  tmv.tm_hour = hh;
  tmv.tm_min = mm;
  tmv.tm_sec = ss;

  // Locate fractional part if any
  const char* tptr = strchr(s, 'T');
  const char* frac = NULL;
  if (tptr) {
    frac = strchr(tptr, '.');
  }

  uint64_t nsec = 0;
  if (frac) {
    ++frac; // first fractional digit
    int digits = 0;
    while (isdigit((unsigned char)frac[digits]) && digits < 9) {
      nsec = nsec * 10u + (uint64_t)(frac[digits] - '0');
      digits++;
    }
    // Scale to nanoseconds if fewer than 9 digits
    while (digits < 9) {
      nsec *= 10u;
      digits++;
    }
  }

  time_t t = timegm_compat(&tmv);
  if (t < 0) return -1;

  *out_ns = (uint64_t)t * 1000000000ull + nsec;
  return 0;
}

// Make the path for an index file relating to the .flsh file being replayed.
static void make_index_path_for_replay(const char* flsh_path,
                                       char* out,
                                       size_t out_cap) {
  if (!flsh_path || !out || out_cap == 0) return;

  size_t len = strlen(flsh_path);
  if (len + 6 > out_cap) {
    out[0] = '\0';
    return;
  }

  memcpy(out, flsh_path, len + 1);
  char* dot = strrchr(out, '.');
  if (dot && strcmp(dot, ".flsh") == 0) {
    strcpy(dot, ".fidx");
  } else {
    strcpy(out + len, ".fidx");
  }
}

// Parse a timestamp into unix_ns.
// Supported forms:
//   Raw integer nanoseconds (e.g. "1731812563123456789")
//   ISO-8601 UTC: "YYYY-MM-DDTHH:MM:SS[.fffffffff]Z"
static int parse_ts_ns(const char* s, uint64_t* out_ns) {
  // Raw integer first
  if (parse_u64(s, out_ns) == 0) {
    return 0;
  }
  // Then ISO-8601
  if (parse_iso8601_ns(s, out_ns) == 0) {
    return 0;
  }
  return -1;
}

// usage
static void replay_usage(void) {
  fprintf(stderr,
          "usage: flash replay [options] FILE.flsh\n"
          "options:\n"
          "  --from-ts TS       Filter records with ts >= TS (ns or ISO-8601 UTC)\n"
          "  --to-ts TS         Filter records with ts <= TS (ns or ISO-8601 UTC)\n"
          "  --limit N          Emit at most N records\n"
          "  --with-ts          Prefix each record with its timestamp (ns)\n"
          "  --data-only        Only emit data records (skip control/meta/run)\n"
          "  --data             Alias for --data-only\n"
          "  --human            Human-readable summary view\n"
          "  --human-readable   Alias for --human\n"
          "  --no-trunc         In --human mode, show full payload (no ... at the end)\n"
          "  --full-payload     Alias for --no-trunc\n"
          "  --no-index         Do not use .fidx index even if present\n");
}

// FSIG detection:
// Scan a window near EOF for the literal bytes "FSIG" and
// treat that offset as the start of the trailer. FRF frames are only
// read from [0 .. fsig_offset).

#define FSIG_SEARCH_WINDOW 4096

static int detect_fsig_offset(const char* path,
                              int* has_fsig,
                              uint64_t* fsig_offset_out) {
  *has_fsig = 0;
  *fsig_offset_out = 0;

  FILE* f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr,
            "flash replay: cannot open '%s' for FSIG scan: %s\n",
            path, strerror(errno));
    return -1;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    fprintf(stderr,
            "flash replay: fseek end failed on '%s': %s\n",
            path, strerror(errno));
    fclose(f);
    return -1;
  }

  long size = ftell(f);
  if (size < 0) {
    fprintf(stderr,
            "flash replay: ftell failed on '%s': %s\n",
            path, strerror(errno));
    fclose(f);
    return -1;
  }

  if (size < 4) {
    fclose(f);
    return 0; // too small to contain "FSIG"
  }

  long window = size < FSIG_SEARCH_WINDOW ? size : FSIG_SEARCH_WINDOW;
  if (fseek(f, size - window, SEEK_SET) != 0) {
    fprintf(stderr,
            "flash replay: fseek window failed on '%s': %s\n",
            path, strerror(errno));
    fclose(f);
    return -1;
  }

  unsigned char buf[FSIG_SEARCH_WINDOW];
  size_t n = fread(buf, 1, (size_t)window, f);
  fclose(f);

  if (n != (size_t)window) {
    // Short read, be conservative and just treat as unsealed
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

  // No FSIG magic found in the tail; treat as unsealed
  return 0;
}

// frame classification / snippets / human formatting
typedef enum {
  FRAME_KIND_UNKNOWN = 0,
  FRAME_KIND_DATA = 1,
  FRAME_KIND_CONTROL = 2
} frame_kind_t;

static const char* frame_kind_name(frame_kind_t k) {
  switch (k) {
    case FRAME_KIND_DATA: return "DATA";
    case FRAME_KIND_CONTROL: return "CONTROL";
    default: return "UNKNOWN";
  }
}

static int contains_substr(const char* hay, size_t hay_len, const char* needle) {
  size_t nlen = strlen(needle);
  if (nlen == 0 || hay_len < nlen) return 0;
  for (size_t i = 0; i + nlen <= hay_len; ++i) {
    if (memcmp(hay + i, needle, nlen) == 0) {
      return 1;
    }
  }
  return 0;
}

// Heuristic to distinguish control vs data frames based on JSON content
static frame_kind_t classify_frame(const unsigned char* buf, uint32_t len) {
  if (!buf || len == 0) {
    // Empty payloads are almost certainly control/meta
    return FRAME_KIND_CONTROL;
  }

  const char* s = (const char*)buf;
  const char* end = s + len;

  // Skip leading whitespace
  while (s < end && isspace((unsigned char)*s)) {
    ++s;
  }
  if (s >= end) {
    return FRAME_KIND_CONTROL;
  }

  if (*s == '{') {
    size_t remain = (size_t)(end - s);
    int has_schema = contains_substr(s, remain, "\"schema_version\"");
    int has_format = contains_substr(s, remain, "\"format\"");
    int has_type_lab = contains_substr(s, remain, "\"type_label\"");
    int has_run_id = contains_substr(s, remain, "\"run_id\"");
    int has_start_ts = contains_substr(s, remain, "\"start_ts\"");
    int has_end_ts = contains_substr(s, remain, "\"end_ts\"");
    int has_status = contains_substr(s, remain, "\"status\"");
    int has_fallback = contains_substr(s, remain, "\"fallback_mode\"");

    if (has_schema && (has_format || has_type_lab || has_fallback ||
                       has_run_id || has_status)) {
      return FRAME_KIND_CONTROL;
    }
    if (has_run_id && (has_start_ts || has_end_ts || has_status)) {
      return FRAME_KIND_CONTROL;
    }
  }

  return FRAME_KIND_DATA;
}

#define SNIPPET_MAX 4096

static void build_snippet(const unsigned char* buf, uint32_t len,
                          char* out, size_t out_cap,
                          int no_trunc) {
  if (!out || out_cap == 0) return;

  size_t limit = len;
  if (!no_trunc && limit > SNIPPET_MAX) {
    limit = SNIPPET_MAX;
  }

  size_t j = 0;
  for (size_t i = 0; i < limit && j + 1 < out_cap; ++i) {
    unsigned char c = buf[i];
    if (c == '\n' || c == '\r') {
      if (j + 1 < out_cap) {
        out[j++] = ' ';
      }
    } else if ((c < 32 && c != '\t') || c == 0x7f) {
      // Non-printables => \xNN
      if (j + 4 >= out_cap) break;
      static const char hex[] = "0123456789abcdef";
      out[j++] = '\\';
      out[j++] = 'x';
      out[j++] = hex[(c >> 4) & 0xF];
      out[j++] = hex[c & 0xF];
    } else {
      out[j++] = (char)c;
    }
  }

  if (!no_trunc && len > limit && j + 3 < out_cap) {
    out[j++] = '.';
    out[j++] = '.';
    out[j++] = '.';
  }

  out[j] = '\0';
}

static void format_ts_human(uint64_t ns, char* buf, size_t buf_sz) {
  if (!buf || buf_sz == 0) return;
  if (ns == 0) {
    snprintf(buf, buf_sz, "NONE");
    return;
  }

  time_t sec = (time_t)(ns / 1000000000ull);
  uint32_t nsec = (uint32_t)(ns % 1000000000ull);

  struct tm tmv;
#if defined(_WIN32)
  gmtime_s(&tmv, &sec);
#else
  gmtime_r(&sec, &tmv);
#endif

  int ms = (int)(nsec / 1000000u);

  snprintf(buf, buf_sz,
           "%04d-%02d-%02d %02d:%02d:%02d.%03d",
           tmv.tm_year + 1900,
           tmv.tm_mon + 1,
           tmv.tm_mday,
           tmv.tm_hour,
           tmv.tm_min,
           tmv.tm_sec,
           ms);
}

// Per-frame info for human mode
typedef struct {
  uint64_t index; // 0-based frame index
  uint64_t ts_ns;
  frame_kind_t  kind;
  uint32_t length;
  char snippet[SNIPPET_MAX + 1];
} frame_info;

static int ensure_frame_capacity(frame_info** arr, size_t* cap, size_t needed) {
  if (*cap >= needed) return 0;
  size_t new_cap = *cap == 0 ? 64 : *cap * 2;
  while (new_cap < needed) new_cap *= 2;
  frame_info* tmp = realloc(*arr, new_cap * sizeof(frame_info));
  if (!tmp) return -1;
  *arr = tmp;
  *cap = new_cap;
  return 0;
}

// main command
int cmd_replay(int argc, char** argv) {
  uint64_t from_ts = 0;
  uint64_t to_ts = 0;
  int have_from = 0;
  int have_to = 0;
  uint64_t limit = 0; // 0 = no limit
  int with_ts = 0;
  int data_only = 0;
  int human = 0;
  int no_trunc = 0;
  int no_index = 0;
  const char* path = NULL;

  // argv[0] is "replay"; flags start at argv[1].
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (arg[0] == '-') {
      if (!strcmp(arg, "--with-ts")) {
        with_ts = 1;
      } else if (!strcmp(arg, "--data-only") || !strcmp(arg, "--data")) {
        data_only = 1;
      } else if (!strcmp(arg, "--human") || !strcmp(arg, "--human-readable")) {
        human = 1;
      } else if (!strcmp(arg, "--no-trunc") || !strcmp(arg, "--full-payload")) {
        no_trunc = 1;
      } else if (!strncmp(arg, "--limit=", 8)) {
        if (parse_u64(arg + 8, &limit) != 0) {
          fprintf(stderr,
                  "flash replay: invalid --limit value: %s\n", arg + 8);
          replay_usage();
          return EX_USAGE;
        }
      } else if (!strcmp(arg, "--no-index")) {
        no_index = 1;
      } else if (!strcmp(arg, "--limit")) {
        if (i + 1 >= argc) {
          fprintf(stderr,
                  "flash replay: --limit requires a value\n");
          replay_usage();
          return EX_USAGE;
        }
        if (parse_u64(argv[++i], &limit) != 0) {
          fprintf(stderr,
                  "flash replay: invalid --limit value: %s\n", argv[i]);
          replay_usage();
          return EX_USAGE;
        }
      } else if (!strncmp(arg, "--from-ts=", 10)) {
        uint64_t tmp = 0;
        if (parse_ts_ns(arg + 10, &tmp) != 0) {
          fprintf(stderr,
                  "flash replay: invalid --from-ts value: %s\n", arg + 10);
          replay_usage();
          return EX_USAGE;
        }
        from_ts = tmp;
        have_from = 1;
      } else if (!strcmp(arg, "--from-ts")) {
        if (i + 1 >= argc) {
          fprintf(stderr,
                  "flash replay: --from-ts requires a value\n");
          replay_usage();
          return EX_USAGE;
        }
        uint64_t tmp = 0;
        if (parse_ts_ns(argv[++i], &tmp) != 0) {
          fprintf(stderr,
                  "flash replay: invalid --from-ts value: %s\n", argv[i]);
          replay_usage();
          return EX_USAGE;
        }
        from_ts = tmp;
        have_from = 1;
      } else if (!strncmp(arg, "--to-ts=", 8)) {
        uint64_t tmp = 0;
        if (parse_ts_ns(arg + 8, &tmp) != 0) {
          fprintf(stderr,
                  "flash replay: invalid --to-ts value: %s\n", arg + 8);
          replay_usage();
          return EX_USAGE;
        }
        to_ts = tmp;
        have_to = 1;
      } else if (!strcmp(arg, "--to-ts")) {
        if (i + 1 >= argc) {
          fprintf(stderr,
                  "flash replay: --to-ts requires a value\n");
          replay_usage();
          return EX_USAGE;
        }
        uint64_t tmp = 0;
        if (parse_ts_ns(argv[++i], &tmp) != 0) {
          fprintf(stderr,
                  "flash replay: invalid --to-ts value: %s\n", argv[i]);
          replay_usage();
          return EX_USAGE;
        }
        to_ts = tmp;
        have_to = 1;
      } else {
        fprintf(stderr,
                "flash replay: unknown option: %s\n", arg);
        replay_usage();
        return EX_USAGE;
      }
    } else {
      if (path) {
        fprintf(stderr,
                "flash replay: multiple files not supported yet\n");
        replay_usage();
        return EX_USAGE;
      }
      path = arg;
    }
  }

  if (!path) {
    replay_usage();
    return EX_USAGE;
  }

  /* Index loading that is optional. Fallback if anything fails. */
  flash_index idx;
  int have_index = 0;
  int idx_is_stale = 0;

  memset(&idx, 0, sizeof(idx));

  if (!no_index) {
    char fidx_path[PATH_MAX];
    make_index_path_for_replay(path, fidx_path, sizeof(fidx_path));
    if (fidx_path[0] != '\0') {
      int rc_idx = flash_index_load(path, fidx_path, &idx, &idx_is_stale);
      if (rc_idx == 0 && !idx_is_stale) {
        have_index = 1;
      } else {
        /* No usable index: just fall back to full scan. */
        flash_index_free(&idx);
        memset(&idx, 0, sizeof(idx));
      }
    }
  }

  // Detect FSIG trailer (if present) so we don't go into it as FRF
  int has_fsig = 0;
  uint64_t fsig_offset = 0;
  if (detect_fsig_offset(path, &has_fsig, &fsig_offset) != 0) {
    // I/O or other fatal error already printed
    return 2;
  }

  frf_handle_t h;
  int rc = frf_open(path, "rb", &h);
  if (rc != 0) {
    fprintf(stderr,
            "flash replay: failed to open '%s' as FRF (rc=%d)\n",
            path, rc);
    return 2;
  }

  frf_file_header_t fh;
  rc = frf_read_and_verify_header(&h, &fh);
  if (rc != 0) {
    fprintf(stderr,
            "flash replay: '%s' is not a valid Flash record file (header rc=%d)\n",
            path, rc);
    frf_close(&h);
    return 2;
  }

  /* Decide where to start reading frames.
   Default: just after the FRF file header. */
  uint64_t start_offset = FRF_FILE_HEADER_BYTES;

  if (have_index && have_from) {
    const flash_index_entry_v1* e =
        flash_index_find_by_ts(&idx, (int64_t)from_ts);
    if (e && e->offset >= FRF_FILE_HEADER_BYTES) {
      start_offset = e->offset;
    }
  }

  if (start_offset != FRF_FILE_HEADER_BYTES) {
    int seek_rc = frf_seek_bytes(&h, start_offset);
    if (seek_rc != 0) {
      fprintf(stderr,
              "flash replay: failed to seek to %" PRIu64 " in '%s'\n",
              start_offset, path);
      flash_index_free(&idx);
      frf_close(&h);
      return 2;
    }
  }

  // Non-human mode: stream payloads directly
  if (!human) {
    uint64_t offset = start_offset;
    uint64_t emitted = 0;
    unsigned char buf[64 * 1024];

    for (;;) {
      // For sealed files, do not go past the FSIG trailer
      if (has_fsig && offset >= fsig_offset) {
        break;
      }

      frf_record_header_t hdr;
      uint32_t payload_len = 0;

      rc = frf_next_record(&h, &hdr, buf, sizeof(buf), &payload_len);

      if (rc == 0) {
        uint64_t ts = hdr.ts_unix_ns;

        // Advance logical FRF offset (header + payload + chain)
        uint64_t frame_bytes =
            (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)hdr.length;
        offset += frame_bytes;

        // Time filters
        if (have_from && ts < from_ts) {
          continue;
        }
        if (have_to && ts > to_ts) {
          continue;
        }

        frame_kind_t kind = classify_frame(buf, payload_len);
        if (data_only && kind != FRAME_KIND_DATA) {
          continue;
        }

        if (limit && emitted >= limit) {
          break;
        }

        // Emit this record
        if (with_ts) {
          if (fprintf(stdout, "%" PRIu64 " ", ts) < 0) {
            fprintf(stderr,
                    "flash replay: write to stdout failed (timestamp)\n");
            frf_close(&h);
            return 2;
          }
        }

        if (payload_len > 0) {
          if (fwrite(buf, 1, payload_len, stdout) != payload_len) {
            fprintf(stderr,
                    "flash replay: write to stdout failed (payload)\n");
            frf_close(&h);
            return 2;
          }
        }

        if (fputc('\n', stdout) == EOF) {
          fprintf(stderr,
                  "flash replay: write to stdout failed (newline)\n");
          frf_close(&h);
          return 2;
        }

        emitted++;
        continue;
      }

      if (rc == 1) {
        // Clean FRF EOF (unsealed file case)
        break;
      }

      // Any negative rc is real FRF corruption in the data section
      fprintf(stderr,
              "flash replay: FRF error in '%s' (rc=%d). File may be corrupted.\n",
              path, rc);
      frf_close(&h);
      return 2;
    }

    frf_close(&h);
    fflush(stdout);
    flash_index_free(&idx);
    return 0;
  }

  // Human-readable mode: gather stats + summaries, then print
  uint64_t offset = start_offset;
  unsigned char buf[64 * 1024];

  frame_info* frames = NULL;
  size_t frames_cap = 0;
  size_t frames_len = 0;
  uint64_t printable_count = 0;

  uint64_t total_frames = 0;
  uint64_t data_frames = 0;
  uint64_t control_frames = 0;
  uint64_t min_ts = 0;
  uint64_t max_ts = 0;

  for (;;) {
    if (has_fsig && offset >= fsig_offset) {
      break;
    }

    frf_record_header_t hdr;
    uint32_t payload_len = 0;
    rc = frf_next_record(&h, &hdr, buf, sizeof(buf), &payload_len);

    if (rc == 0) {
      uint64_t ts = hdr.ts_unix_ns;
      uint64_t frame_bytes =
          (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)hdr.length;
      offset += frame_bytes;
      total_frames++;

      if (ts > 0) {
        if (min_ts == 0 || ts < min_ts) min_ts = ts;
        if (ts > max_ts) max_ts = ts;
      }

      frame_kind_t kind = classify_frame(buf, payload_len);
      if (kind == FRAME_KIND_DATA) data_frames++;
      else control_frames++;

      int passes_time = 1;
      if (have_from && ts < from_ts) passes_time = 0;
      if (have_to && ts > to_ts) passes_time = 0;

      int include_for_print = passes_time;
      if (include_for_print && data_only && kind != FRAME_KIND_DATA) {
        include_for_print = 0;
      }

      if (include_for_print) {
        if (!limit || printable_count < limit) {
          if (ensure_frame_capacity(&frames, &frames_cap, frames_len + 1) != 0) {
            fprintf(stderr,
                    "flash replay: out of memory while building human view\n");
            free(frames);
            frf_close(&h);
            return 2;
          }
          frame_info* fi = &frames[frames_len++];
          fi->index = total_frames - 1;
          fi->ts_ns = ts;
          fi->kind = kind;
          fi->length = hdr.length;
          build_snippet(buf, payload_len, fi->snippet, sizeof(fi->snippet), no_trunc);
          printable_count++;
        }
      }

      continue;
    }

    if (rc == 1) {
      // Clean FRF EOF
      break;
    }

    fprintf(stderr,
            "flash replay: FRF error in '%s' (rc=%d). File may be corrupted.\n",
            path, rc);
    free(frames);
    frf_close(&h);
    return 2;
  }

  frf_close(&h);

  // Summary header
  printf("File: %s\n", path);
  printf("Sealed: %s\n", has_fsig ? "yes" : "no");
  printf("Frames: %" PRIu64 " total (%" PRIu64 " data, %" PRIu64 " control)\n",
         total_frames, data_frames, control_frames);

  if (min_ts > 0 && max_ts >= min_ts) {
    char buf_start[64];
    char buf_end[64];
    format_ts_human(min_ts, buf_start, sizeof(buf_start));
    format_ts_human(max_ts, buf_end, sizeof(buf_end));
    double delta_s = (double)(max_ts - min_ts) / 1e9;
    printf("Time range: %s  ->  %s  (%.6f s span)\n",
           buf_start, buf_end, delta_s);
  } else {
    printf("Time range: (no timestamps)\n");
  }

  printf("\nFrames");
  if (limit && printable_count >= limit) {
    printf(" (first %" PRIu64 " matching)", printable_count);
  }
  printf(":\n");

  for (size_t i = 0; i < frames_len; ++i) {
    const frame_info* fi = &frames[i];
    char tsbuf[64];
    format_ts_human(fi->ts_ns, tsbuf, sizeof(tsbuf));
    printf("  [%" PRIu64 "] kind=%-7s ts=%s len=%" PRIu32 "  %s\n",
           fi->index,
           frame_kind_name(fi->kind),
           tsbuf,
           fi->length,
           fi->snippet);
  }

  free(frames);
  fflush(stdout);
  flash_index_free(&idx);
  return 0;
}
