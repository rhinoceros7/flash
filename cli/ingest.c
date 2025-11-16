#include "ingest.h"
#include "frf.h"
#include "ingest_formats.h"
#include "ingest_source.h"
#include "flash/seal.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <sys/stat.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#define FRF_TYPE_STREAM_META 0xFFFFFF00u
#define META_BUF_SIZE 2048
#define PATH_BUF_SIZE 1024
#define FRF_TYPE_RUN_OPEN 0xFFFFFF01u
#define FRF_TYPE_RUN_CLOSE 0xFFFFFF02u

typedef struct {
  const ingest_config* base;
  ingest_config active;
  const char* type_label;
  uint32_t type_id;
  int fallback_used;
} ingest_runtime;

typedef struct {
  frf_handle_t handle;
  int open;
  char path[PATH_BUF_SIZE];
  uint64_t bytes;
  uint64_t records;
  uint64_t created_ns;
  uint64_t last_ts_ns;
} output_file;

static uint64_t now_ns(void) {
#ifdef _WIN32
  FILETIME ft;
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0602
  GetSystemTimePreciseAsFileTime(&ft);
#else
  GetSystemTimeAsFileTime(&ft);
#endif
  ULARGE_INTEGER uli;
  uli.LowPart = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;
  const uint64_t EPOCH_DIFF_100NS = 11644473600ULL * 10000000ULL;
  uint64_t ns100 = uli.QuadPart;
  if (ns100 <= EPOCH_DIFF_100NS) {
    return 0;
  }
  return (ns100 - EPOCH_DIFF_100NS) * 100ULL;
#else
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static uint32_t hash_type_label(const char* label) {
  const unsigned char* p = (const unsigned char*)label;
  uint32_t h = 2166136261u;
  while (*p) {
    h ^= (uint32_t)(*p++);
    h *= 16777619u;
  }
  return h;
}

static const char* format_to_string(int fmt) {
  switch (fmt) {
    case FMT_LINES: return "lines";
    case FMT_NDJSON: return "lines+json";
    case FMT_JSON: return "json";
    case FMT_CSV: return "csv";
    case FMT_LEN4: return "len4";
    case FMT_RAW: return "raw";
    default: return "unknown";
  }
}

static const char* source_to_string(int kind) {
  switch (kind) {
    case SRC_STDIN: return "stdin";
    case SRC_FILE: return "file";
    case SRC_DIR: return "dir";
    case SRC_TCP: return "tcp";
    case SRC_UDP: return "udp";
    case SRC_SERIAL: return "serial";
    case SRC_HTTP: return "http";
    case SRC_SSE: return "sse";
    case SRC_WS: return "ws";
    default: return "unknown";
  }
}

static const char* infer_type_label_for_format(int fmt) {
  switch (fmt) {
    case FMT_LINES: return "lines_v1";
    case FMT_NDJSON: return "ndjson_v1";
    case FMT_JSON: return "json_v1";
    case FMT_CSV: return "csv_v1";
    case FMT_LEN4: return "bytes_v1";
    case FMT_RAW: return "bytes_v1";
    default: return "bytes_v1";
  }
}

static int path_exists(const char* path) {
  struct stat st;
  return stat(path, &st) == 0;
}

static void ensure_active_label(ingest_runtime* rt) {
  if (!rt->type_label || rt->type_label[0] == '\0') {
    rt->type_label = infer_type_label_for_format(rt->active.fmt);
  }
  rt->type_id = hash_type_label(rt->type_label);
}

static void init_runtime(const ingest_config* cfg, ingest_runtime* rt) {
  memset(rt, 0, sizeof(*rt));
  rt->base = cfg;
  rt->active = *cfg;
  rt->type_label = cfg->type_label;
  ensure_active_label(rt);
}

static void format_rotation_value(uint64_t value, char* out, size_t cap, const char* kind) {
  if (value == 0) {
    snprintf(out, cap, "null");
    return;
  }
  if (strcmp(kind, "size") == 0) {
    if (value % (1024ULL * 1024ULL * 1024ULL) == 0) {
      snprintf(out, cap, "%lluG", (unsigned long long)(value / (1024ULL * 1024ULL * 1024ULL)));
    } else if (value % (1024ULL * 1024ULL) == 0) {
      snprintf(out, cap, "%lluM", (unsigned long long)(value / (1024ULL * 1024ULL)));
    } else if (value % 1024ULL == 0) {
      snprintf(out, cap, "%lluK", (unsigned long long)(value / 1024ULL));
    } else {
      snprintf(out, cap, "%llu", (unsigned long long)value);
    }
  } else if (strcmp(kind, "time") == 0) {
    uint64_t seconds = value;
    if (seconds % 3600ULL == 0) {
      snprintf(out, cap, "%lluh", (unsigned long long)(seconds / 3600ULL));
    } else if (seconds % 60ULL == 0) {
      snprintf(out, cap, "%llum", (unsigned long long)(seconds / 60ULL));
    } else {
      snprintf(out, cap, "%llus", (unsigned long long)seconds);
    }
  } else {
    if (value % 1000000ULL == 0) {
      snprintf(out, cap, "%lluM", (unsigned long long)(value / 1000000ULL));
    } else if (value % 1000ULL == 0) {
      snprintf(out, cap, "%lluk", (unsigned long long)(value / 1000ULL));
    } else {
      snprintf(out, cap, "%llu", (unsigned long long)value);
    }
  }
}

static void describe_rotation(const ingest_config* cfg, char* out, size_t cap) {
  if (cfg->rotate_bytes == 0 && cfg->rotate_seconds == 0 && cfg->rotate_records == 0) {
    snprintf(out, cap, "off");
    return;
  }
  char size_buf[32];
  char time_buf[32];
  char rec_buf[32];
  format_rotation_value(cfg->rotate_bytes, size_buf, sizeof(size_buf), "size");
  format_rotation_value(cfg->rotate_seconds, time_buf, sizeof(time_buf), "time");
  format_rotation_value(cfg->rotate_records, rec_buf, sizeof(rec_buf), "records");
  snprintf(out, cap, "size=%s,time=%s,records=%s", size_buf, time_buf, rec_buf);
}

static void format_source_plan(const ingest_config* cfg, char* out, size_t cap) {
  const char* kind = source_to_string(cfg->src_kind);
  if (cfg->src_detail && cfg->src_detail[0]) {
    snprintf(out, cap, "%s(%s)", kind, cfg->src_detail);
  } else {
    snprintf(out, cap, "%s", kind);
  }
}

static void json_escape_string(const char* in, char* out, size_t cap) {
  if (!in) in = "";
  size_t used = 0;
  for (const unsigned char* p = (const unsigned char*)in; *p && used + 1 < cap; ++p) {
    const char* replacement = NULL;
    char unicode_buf[7];
    switch (*p) {
      case '"': replacement = "\\\""; break;
      case '\\': replacement = "\\\\"; break;
      case '\b': replacement = "\\b"; break;
      case '\f': replacement = "\\f"; break;
      case '\n': replacement = "\\n"; break;
      case '\r': replacement = "\\r"; break;
      case '\t': replacement = "\\t"; break;
      default:
        if (*p < 0x20) {
          snprintf(unicode_buf, sizeof(unicode_buf), "\\u%04x", *p);
          replacement = unicode_buf;
        }
        break;
    }
    if (replacement) {
      size_t need = strlen(replacement);
      if (used + need >= cap) break;
      memcpy(out + used, replacement, need);
      used += need;
    } else {
      out[used++] = (char)*p;
    }
  }
  if (used >= cap) used = cap - 1;
  out[used] = '\0';
}

static int build_meta_json(const ingest_runtime* rt, const ingest_decoder* dec, const ingest_config* cfg, char* buf, size_t cap) {
  char type_buf[256];
  char detail_buf[256];
  json_escape_string(rt->type_label ? rt->type_label : "", type_buf, sizeof(type_buf));
  json_escape_string(cfg->src_detail ? cfg->src_detail : "", detail_buf, sizeof(detail_buf));

  char rotate_size[32];
  char rotate_time[32];
  char rotate_records[32];
  format_rotation_value(cfg->rotate_bytes, rotate_size, sizeof(rotate_size), "size");
  format_rotation_value(cfg->rotate_seconds, rotate_time, sizeof(rotate_time), "time");
  format_rotation_value(cfg->rotate_records, rotate_records, sizeof(rotate_records), "records");

  const ingest_timestamp_policy* ts = &dec->ts_policy;
  const char* ts_source = ts->source ? ts->source : "now";
  const char* ts_parsed = ts->parsed ? ts->parsed : "none";
  char ts_field_buf[128];
  ts_field_buf[0] = '\0';
  if (ts->field) {
    json_escape_string(ts->field, ts_field_buf, sizeof(ts_field_buf));
  }

  const char* field_json = "null";
  char field_holder[136];
  if (ts->field) {
    snprintf(field_holder, sizeof(field_holder), "\"%s\"", ts_field_buf);
    field_json = field_holder;
  }

  int written = snprintf(buf, cap,
    "{\n"
    "  \"schema_version\": 1,\n"
    "  \"format\": \"%s\",\n"
    "  \"type_label\": \"%s\",\n"
    "  \"source\": {\"kind\": \"%s\", \"detail\": \"%s\"},\n"
    "  \"timestamp_policy\": {\"source\": \"%s\", \"field\": %s, \"parsed\": \"%s\"},\n"
    "  \"rotate\": {\"size\": %s, \"time\": %s, \"records\": %s},\n"
    "  \"fallback_mode\": \"%s\"\n"
    "}",
    format_to_string(rt->active.fmt),
    type_buf,
    source_to_string(cfg->src_kind),
    detail_buf,
    ts_source,
    field_json,
    ts_parsed,
    cfg->rotate_bytes ? rotate_size : "null",
    cfg->rotate_seconds ? rotate_time : "null",
    cfg->rotate_records ? rotate_records : "null",
    cfg->strict ? "strict" : "soft");
  if (written < 0 || (size_t)written >= cap) {
    return -1;
  }
  return written;
}

static void close_output(output_file* out) {
  if (out->open) {
    frf_close(&out->handle);
    out->open = 0;
  }
}

static int open_output(const char* path, output_file* out) {
  memset(out, 0, sizeof(*out));
  if (frf_open(path, "wb+", &out->handle) != 0) {
    return -1;
  }
  out->open = 1;
  strncpy(out->path, path, sizeof(out->path) - 1);
  out->path[sizeof(out->path) - 1] = '\0';
  out->created_ns = now_ns();
  if (frf_write_header_if_new(&out->handle, out->created_ns) != 0) {
    frf_close(&out->handle);
    out->open = 0;
    return -1;
  }
  return 0;
}

static void print_timestamp_banner(const ingest_decoder* dec) {
  if (dec->ts_policy_reported) return;
  ingest_decoder* non_const = (ingest_decoder*)dec;
  non_const->ts_policy_reported = 1;
  const char* src = dec->ts_policy.source ? dec->ts_policy.source : "now";
  if (dec->ts_policy.field) {
    fprintf(stderr, "timestamp: source=field(\"%s\") format=%s\n", dec->ts_policy.field, dec->ts_policy.parsed ? dec->ts_policy.parsed : "none");
  } else {
    fprintf(stderr, "timestamp: source=%s\n", src);
  }
}

static int write_meta_frame(output_file* out, const ingest_runtime* rt, ingest_decoder* decoder) {
  char meta_buf[META_BUF_SIZE];
  int meta_len = build_meta_json(rt, decoder, &rt->active, meta_buf, sizeof(meta_buf));
  if (meta_len < 0) { fprintf(stderr, "failed to build meta json\n"); return -1; }
  if (frf_append_record(&out->handle, FRF_TYPE_STREAM_META, 0 /*ts=now in frf*/, meta_buf, (uint32_t)meta_len) != 0) {
    fprintf(stderr, "failed to write META frame\n"); return -1;
  }
  fprintf(stderr, "meta: path=%s format=%s type=%s\n", out->path, format_to_string(rt->active.fmt), rt->type_label);
  return 0;
}

static int write_run_open(output_file* out, const ingest_runtime* rt) {
  (void)rt; // reserved for future use
  char buf[256];
  int n = snprintf(buf, sizeof(buf),
      "{\"schema_version\":1,\"run_id\":\"%llu\",\"start_ts\":%llu}",
      (unsigned long long)out->created_ns,
      (unsigned long long)out->created_ns);
  if (n < 0 || (size_t)n >= sizeof(buf)) return -1;
  return frf_append_record(&out->handle, FRF_TYPE_RUN_OPEN, 0, buf, (uint32_t)n);
}

static int write_run_close_clean(output_file* out) {
  char buf[256];
  int n = snprintf(buf, sizeof(buf),
    "{\"schema_version\":1,\"run_id\":\"%llu\",\"end_ts\":%llu,\"status\":\"CLEAN\"}",
    (unsigned long long)out->created_ns,
    (unsigned long long)out->last_ts_ns);
  if (n < 0 || (size_t)n >= sizeof(buf)) return -1;
  return frf_append_record(&out->handle, FRF_TYPE_RUN_CLOSE, 0, buf, (uint32_t)n);
}

static int ensure_timestamp_policy(ingest_decoder* decoder) {
  if (!decoder->ts_policy.source) {
    decoder->ts_policy.source = "now";
    decoder->ts_policy.field = NULL;
    decoder->ts_policy.parsed = "none";
  }
  return 0;
}

static void summary(const output_file* out, uint64_t frames) {
  if (!out->open) return;
  fprintf(stderr, "close: path=%s records=%llu last_ts=%llu\n", out->path, (unsigned long long)frames, (unsigned long long)out->last_ts_ns);
}

static void copy_path(char* dst, size_t cap, const char* src) {
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = '\0';
}

static void derive_rotated_name(const char* base, char* out, size_t cap) {
  time_t t = time(NULL);
  struct tm tmv;
#ifdef _WIN32
  gmtime_s(&tmv, &t);
#else
  gmtime_r(&t, &tmv);
#endif
  const char* slash = strrchr(base, '/');
#ifdef _WIN32
  const char* backslash = strrchr(base, '\\');
  if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
  const char* fname = slash ? slash + 1 : base;
  char dir[PATH_BUF_SIZE];
  if (slash) {
    size_t dir_len = (size_t)(slash - base);
    if (dir_len >= sizeof(dir)) dir_len = sizeof(dir) - 1;
    memcpy(dir, base, dir_len);
    dir[dir_len] = '\0';
  } else {
    dir[0] = '\0';
  }
  const char* ext = strrchr(fname, '.');
  char stem[PATH_BUF_SIZE];
  if (ext && strcmp(ext, ".flsh") == 0) {
    size_t stem_len = (size_t)(ext - fname);
    if (stem_len >= sizeof(stem)) stem_len = sizeof(stem) - 1;
    memcpy(stem, fname, stem_len);
    stem[stem_len] = '\0';
  } else {
    copy_path(stem, sizeof(stem), fname);
    ext = ".flsh";
  }
  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &tmv);
  if (dir[0]) {
    snprintf(out, cap, "%s/%s_%s%s", dir, stem, timestamp, ext);
  } else {
    snprintf(out, cap, "%s_%s%s", stem, timestamp, ext);
  }
}

int flash_ingest_run(const ingest_config* cfg) {
  if (!cfg || !cfg->out_path) { fprintf(stderr, "ingest: invalid configuration\n"); return 1; }

  ingest_runtime rt;
  init_runtime(cfg, &rt);

  /* open source */
  ingest_source* source = NULL; char err[256];
  if (ingest_source_open(&rt.active, &source, err, sizeof(err)) != 0) {
    fprintf(stderr, "ingest: %s\n", err);
    return 1;
  }

  /* build decoder (handles AUTO sniff internally) */
  ingest_decoder dec;
  if (make_decoder(&rt.active, source, &dec) != 0) {
    fprintf(stderr, "ingest: failed to create decoder\n");
    ingest_source_close(source);
    return 1;
  }

  /* stamp final format before opening output and writing META */
  if (dec.resolved_fmt != 0) {
    rt.active.fmt = dec.resolved_fmt;
  }
  rt.type_label = infer_type_label_for_format(rt.active.fmt);
  rt.type_id = hash_type_label(rt.type_label);

  char rotate_desc[128]; describe_rotation(&rt.active, rotate_desc, sizeof(rotate_desc));
  char source_desc[256]; format_source_plan(&rt.active, source_desc, sizeof(source_desc));
  fprintf(stderr, "ingest: source=%s, format=%s, type=%s, rotate=%s, mode=%s\n",
          source_desc, format_to_string(rt.active.fmt), rt.type_label, rotate_desc,
          rt.active.strict ? "strict" : "soft");

  /* decide output path (rotate if exists) */
  output_file out = {0};
  char current_path[PATH_BUF_SIZE];
  if (path_exists(rt.active.out_path)) derive_rotated_name(rt.active.out_path, current_path, sizeof(current_path));
  else                                copy_path(current_path, sizeof(current_path), rt.active.out_path);

  /* OPEN OUTPUT IMMEDIATELY and write META NOW */
  if (open_output(current_path, &out) != 0) {
    fprintf(stderr, "ingest: failed to open %s\n", current_path);
    destroy_decoder(&dec);
    ingest_source_close(source);
    return 1;
  }
  if (write_meta_frame(&out, &rt, &dec) != 0) {
    close_output(&out);
    destroy_decoder(&dec);
    ingest_source_close(source);
    return 1;
  }

  // Mark run start
  (void)write_run_open(&out, &rt);

  print_timestamp_banner(&dec);

  /* main loop */
  uint8_t* payload = NULL;
  uint32_t payload_len = 0;
  uint64_t ts_ns = 0;

  for (;;) {
    /* pull next record */
    {
      uint8_t* p = NULL; uint32_t L = 0; uint64_t T = 0;
      int status = dec.next(&dec, &p, &L, &T);

      if (status == DECODER_STATUS_MISMATCH) {
        if (rt.active.strict) {
          fprintf(stderr, "ingest: decoder(%s) mismatch and strict mode enabled; aborting\n", format_to_string(rt.active.fmt));
          break;
        }
        if (!rt.fallback_used) {
          fprintf(stderr, "decoder(%s) mismatch -> falling back to raw\n", format_to_string(rt.active.fmt));
          rt.fallback_used = 1;
        }
        if (dec.pending_raw && dec.pending_raw_len) {
          ingest_source_unread(dec.source, dec.pending_raw, dec.pending_raw_len);
          free(dec.pending_raw); dec.pending_raw = NULL; dec.pending_raw_len = 0;
        }
        destroy_decoder(&dec);
        rt.active.fmt = FMT_RAW;
        rt.type_label = infer_type_label_for_format(FMT_RAW);
        rt.type_id = hash_type_label(rt.type_label);
        if (make_decoder(&rt.active, source, &dec) != 0) {
          fprintf(stderr, "ingest: failed to create RAW decoder after fallback\n");
          break;
        }
        /* rotate to a new file segment so META stays truthful */
        close_output(&out);
        derive_rotated_name(rt.active.out_path, current_path, sizeof(current_path));
        if (open_output(current_path, &out) != 0) { fprintf(stderr, "ingest: failed to open rotated output '%s'\n", current_path); break; }
        if (write_meta_frame(&out, &rt, &dec) != 0) { break; }
        print_timestamp_banner(&dec);
        continue; /* fetch next record with RAW */
      }

      if (status == DECODER_STATUS_EOF) {
        payload = NULL;
        break;
      }
      if (status == DECODER_STATUS_ERROR) {
        fprintf(stderr, "ingest: decoder error\n");
        payload = NULL;
        break;
      }
      payload = p; payload_len = L; ts_ns = T ? T : 0;
    }

    if (!payload) continue;

    ensure_timestamp_policy(&dec);

    /* rotation checks */
    int rotate_reason = 0;
    if (rt.active.rotate_records && out.records + 1 > rt.active.rotate_records) rotate_reason = 1;
    if (!rotate_reason && rt.active.rotate_bytes && out.bytes + payload_len > rt.active.rotate_bytes) rotate_reason = 2;
    if (!rotate_reason && rt.active.rotate_seconds && (now_ns() - out.created_ns) >= rt.active.rotate_seconds * 1000000000ull) rotate_reason = 3;

    if (rotate_reason) {
      char next_path[PATH_BUF_SIZE];
      derive_rotated_name(rt.active.out_path, next_path, sizeof(next_path));
      fprintf(stderr, "rotate: reason=%s records=%llu bytes=%llu next=%s\n",
              rotate_reason == 1 ? "records" : rotate_reason == 2 ? "size" : "time",
              (unsigned long long)out.records, (unsigned long long)out.bytes, next_path);
      (void)write_run_close_clean(&out);

      // Capture chain tip and record count
      uint8_t chain_tip_prev[32];
      frf_get_chain_tip(&out.handle, chain_tip_prev);
      uint64_t records_prev = out.records;
      summary(&out, out.records);
      close_output(&out);

      // Seal closed segment
      (void)flash_seal_append_fsig(current_path, FLASH_SEAL_CLEAN, 0,
                                      chain_tip_prev, records_prev, NULL);

      copy_path(current_path, sizeof(current_path), next_path);
      if (open_output(current_path, &out) != 0) { fprintf(stderr, "ingest: failed to open %s\n", current_path); free(payload); payload = NULL; break; }
      if (write_meta_frame(&out, &rt, &dec) != 0) { free(payload); payload = NULL; break; }
      write_run_open(&out, &rt);
      print_timestamp_banner(&dec);
    }

    if (frf_append_record(&out.handle, rt.type_id, ts_ns ? ts_ns : now_ns(), payload, payload_len) != 0) {
      fprintf(stderr, "ingest: failed to append record\n");
      free(payload); payload = NULL; break;
    }
    out.bytes += payload_len;
    out.records += 1;
    out.last_ts_ns = ts_ns ? ts_ns : now_ns();

    free(payload); payload = NULL;
  }

  destroy_decoder(&dec);
  int close_status = ingest_source_close(source);
  // Final clean close and seal the last segment
  if (out.open) {
    (void)write_run_close_clean(&out);
    uint8_t chain_tip[32];
    frf_get_chain_tip(&out.handle, chain_tip);
    uint64_t records_final = out.records;
    summary(&out, out.records);
    close_output(&out);
    flash_seal_result fsr;
    int s_rc = flash_seal_append_fsig(current_path, FLASH_SEAL_CLEAN, 0,
                                      chain_tip, records_final, &fsr);
    if (s_rc != 0) {
      fprintf(stderr, "seal: failed (%d); file remains unsealed\n", s_rc);
    } else {
      fprintf(stderr, "seal: kid=%02x%02x%02x%02x%02x%02x%02x%02x signed_length=%llu\n",
              fsr.kid[0],fsr.kid[1],fsr.kid[2],fsr.kid[3],fsr.kid[4],fsr.kid[5],fsr.kid[6],fsr.kid[7],
              (unsigned long long)fsr.signed_length);
    }
  } else {
    // nothing to seal (no open output)
  }
  if (out.records == 0 && close_status != 0) return 1;
  return 0;
}