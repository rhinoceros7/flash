#include "ingest_formats.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <strings.h>
#endif

#define MAX_PAYLOAD_BYTES (16 * 1024 * 1024)
#define RAW_CHUNK_BYTES (64 * 1024)

static uint64_t now_ns(void) {
#ifdef _WIN32
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  ULARGE_INTEGER uli;
  uli.LowPart = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;
  uint64_t ns100 = uli.QuadPart; // 100ns ticks since 1601
  uint64_t ns = ns100 * 100;
  const uint64_t EPOCH_DIFF = 11644473600ULL * 1000000000ULL;
  return ns - EPOCH_DIFF;
#else
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static const char* skip_ws(const char* s) {
  while (*s && isspace((unsigned char)*s)) ++s;
  return s;
}

static int parse_unix_numeric(const char* s, size_t len, uint64_t* out_ns, const char** parsed) {
  char buf[64];
  if (len >= sizeof(buf)) len = sizeof(buf) - 1;
  memcpy(buf, s, len);
  buf[len] = '\0';
  char* end;
  errno = 0;
  long long val = strtoll(buf, &end, 10);
  if (errno != 0 || end == buf) {
    return -1;
  }
  size_t digits = (size_t)(end - buf);
  if (digits >= 19) {
    *out_ns = (uint64_t)val;
    if (parsed) *parsed = "unix_ns";
    return 0;
  }
  *out_ns = (uint64_t)val * 1000000ull;
  if (parsed) *parsed = "unix_ms";
  return 0;
}

static int parse_rfc3339_fragment(const char* s, size_t len, uint64_t* out_ns, const char** parsed) {
  int year, mon, day, hour, min, sec;
  double frac = 0.0;
  char tz_sign = '+';
  int tz_hour = 0, tz_min = 0;
  if (len > 128) len = 128;
  char buf[129];
  memcpy(buf, s, len);
  buf[len] = '\0';
  const char* p = buf;
  if (sscanf(p, "%4d-%2d-%2dT%2d:%2d:%2d", &year, &mon, &day, &hour, &min, &sec) != 6) {
    return -1;
  }
  p = strchr(p, 'T');
  if (!p) return -1;
  p = strchr(p, ':');
  if (!p) return -1;
  p = strchr(p + 1, ':');
  if (!p) return -1;
  p = strchr(p + 1, ':');
  if (!p) return -1;
  p++;
  if (*p == '.') {
    char* frac_end;
    frac = strtod(p, &frac_end);
    p = frac_end;
  }
  if (*p == 'Z' || *p == '\0') {
    tz_sign = '+';
    tz_hour = tz_min = 0;
  } else if (*p == '+' || *p == '-') {
    tz_sign = *p;
    if (sscanf(p + 1, "%2d:%2d", &tz_hour, &tz_min) != 2) return -1;
  }
  struct tm tmv;
  memset(&tmv, 0, sizeof(tmv));
  tmv.tm_year = year - 1900;
  tmv.tm_mon = mon - 1;
  tmv.tm_mday = day;
  tmv.tm_hour = hour;
  tmv.tm_min = min;
  tmv.tm_sec = sec;
#ifdef _WIN32
  time_t t = _mkgmtime(&tmv);
#else
  time_t t = timegm(&tmv);
#endif
  if (t == (time_t)-1) return -1;
  int offset = tz_hour * 60 + tz_min;
  if (tz_sign == '-') offset = -offset;
  t -= offset * 60;
  uint64_t ns = (uint64_t)t * 1000000000ull + (uint64_t)(frac * 1000000000.0 + 0.5);
  *out_ns = ns;
  if (parsed) *parsed = "rfc3339";
  return 0;
}

static int parse_timestamp_field(const char* value, size_t len, uint64_t* out_ns, const char** parsed) {
  const char* s = skip_ws(value);
  size_t trim_len = len - (s - value);
  while (trim_len > 0 && isspace((unsigned char)s[trim_len - 1])) {
    --trim_len;
  }
  if (trim_len == 0) return -1;
  if (s[0] == '\"') {
    if (trim_len < 2) return -1;
    s += 1;
    trim_len -= 2;
    if (parse_rfc3339_fragment(s, trim_len, out_ns, parsed) == 0) {
      return 0;
    }
    return -1;
  }
  return parse_unix_numeric(s, trim_len, out_ns, parsed);
}

static const char* candidate_fields[] = {"ts", "time", "timestamp", "created_at"};

static int equals_ignore_case(const char* a, const char* b) {
#ifdef _WIN32
  return _stricmp(a, b) == 0;
#else
  return strcasecmp(a, b) == 0;
#endif
}

static int find_json_value(const char* json, const char* field, const char** value_start, size_t* value_len, int* is_string) {
  size_t field_len = strlen(field);
  const char* p = json;
  while ((p = strstr(p, "\"")) != NULL) {
    ++p;
    if (strncmp(p, field, field_len) == 0 && p[field_len] == '\"') {
      const char* after = p + field_len + 1;
      after = skip_ws(after);
      if (*after != ':') {
        continue;
      }
      ++after;
      after = skip_ws(after);
      if (*after == '\"') {
        const char* val_start = after;
        ++after;
        int escape = 0;
        while (*after) {
          if (*after == '\\' && !escape) {
            escape = 1;
            ++after;
            continue;
          }
          if (*after == '"' && !escape) {
            size_t len = (size_t)(after - val_start + 1);
            *value_start = val_start;
            *value_len = len;
            if (is_string) *is_string = 1;
            return 0;
          }
          escape = 0;
          ++after;
        }
        return -1;
      } else {
        const char* val_start = after;
        while (*after && *after != ',' && *after != '}' && *after != ']' && !isspace((unsigned char)*after)) {
          ++after;
        }
        size_t len = (size_t)(after - val_start);
        *value_start = val_start;
        *value_len = len;
        if (is_string) *is_string = 0;
        return 0;
      }
    }
  }
  return -1;
}

static void set_timestamp_policy(ingest_decoder* dec, const char* source, const char* field, const char* parsed) {
  dec->ts_policy.source = source;
  dec->ts_policy.field = field;
  dec->ts_policy.parsed = parsed;
}

/* lines decoder */

typedef struct {
  // no state
  int dummy;
} lines_state;

static int decoder_lines_next(ingest_decoder* dec, uint8_t** payload, uint32_t* len, uint64_t* ts_ns) {
  size_t cap = 256;
  size_t used = 0;
  char* buf = (char*)malloc(cap);
  if (!buf) return DECODER_STATUS_ERROR;
  int status;
  for (;;) {
    int ch;
    status = ingest_source_getc(dec->source, &ch);
    if (status == SOURCE_STATUS_ERROR) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    if (status == SOURCE_STATUS_EOF) {
      if (used == 0) {
        free(buf);
        return DECODER_STATUS_EOF;
      }
      break;
    }
    if (ch == '\n') {
      break;
    }
    if (used + 1 >= cap) {
      cap *= 2;
      if (cap > MAX_PAYLOAD_BYTES) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      char* tmp = (char*)realloc(buf, cap);
      if (!tmp) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      buf = tmp;
    }
    buf[used++] = (char)ch;
  }
  if (used > 0 && buf[used - 1] == '\r') used--;
  *payload = (uint8_t*)buf;
  *len = (uint32_t)used;
  *ts_ns = now_ns();
  return DECODER_STATUS_OK;
}

static void decoder_lines_close(ingest_decoder* dec) {
  (void)dec;
}

static int decoder_lines_init(ingest_decoder* dec, const ingest_config* cfg, ingest_source* source) {
  (void)cfg;
  dec->source = source;
  set_timestamp_policy(dec, "now", NULL, "none");
  return 0;
}

/* lines+json decoder */

typedef struct {
  int dummy;
} lines_json_state;

static int decoder_lines_json_next(ingest_decoder* dec, uint8_t** payload, uint32_t* len, uint64_t* ts_ns) {
  size_t cap = 256;
  size_t used = 0;
  char* buf = (char*)malloc(cap);
  if (!buf) return DECODER_STATUS_ERROR;
  int status;
  int newline_seen = 0;
  for (;;) {
    int ch;
    status = ingest_source_getc(dec->source, &ch);
    if (status == SOURCE_STATUS_ERROR) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    if (status == SOURCE_STATUS_EOF) {
      if (used == 0) {
        free(buf);
        return DECODER_STATUS_EOF;
      }
      break;
    }
    if (ch == '\n') {
      newline_seen = 1;
      break;
    }
    if (used + 1 >= cap) {
      cap *= 2;
      if (cap > MAX_PAYLOAD_BYTES) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      char* tmp = (char*)realloc(buf, cap);
      if (!tmp) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      buf = tmp;
    }
    buf[used++] = (char)ch;
  }
  if (used > 0 && buf[used - 1] == '\r') used--;
  if (used == 0) {
    free(buf);
    return decoder_lines_json_next(dec, payload, len, ts_ns);
  }
  const char* trimmed = skip_ws(buf);
  size_t trimmed_len = used - (size_t)(trimmed - buf);
  while (trimmed_len > 0 && isspace((unsigned char)trimmed[trimmed_len - 1])) trimmed_len--;
  if (trimmed_len == 0 || trimmed[0] != '{') {
    size_t stash_len = used + (newline_seen ? 1 : 0);
    dec->pending_raw = (uint8_t*)malloc(stash_len);
    if (dec->pending_raw) {
      memcpy(dec->pending_raw, buf, used);
      if (newline_seen) {
        dec->pending_raw[used] = '\n';
      }
      dec->pending_raw_len = (uint32_t)stash_len;
    }
    free(buf);
    return DECODER_STATUS_MISMATCH;
  }
  uint64_t ts = now_ns();
  const char* parsed = "none";
  int found = 0;
  for (size_t i = 0; i < sizeof(candidate_fields)/sizeof(candidate_fields[0]); ++i) {
    const char* start;
    size_t value_len;
    int is_str;
    if (find_json_value(trimmed, candidate_fields[i], &start, &value_len, &is_str) == 0) {
      if (parse_timestamp_field(start, value_len, &ts, &parsed) == 0) {
        set_timestamp_policy(dec, "field", candidate_fields[i], parsed);
        found = 1;
        break;
      }
    }
  }
  if (!found && dec->ts_policy.source == NULL) {
    set_timestamp_policy(dec, "now", NULL, "none");
  }
  *payload = (uint8_t*)buf;
  *len = (uint32_t)used;
  *ts_ns = ts;
  return DECODER_STATUS_OK;
}

static void decoder_lines_json_close(ingest_decoder* dec) {
  (void)dec;
}

static int decoder_lines_json_init(ingest_decoder* dec, const ingest_config* cfg, ingest_source* source) {
  (void)cfg;
  dec->source = source;
  dec->ts_policy.source = NULL;
  dec->ts_policy.field = NULL;
  dec->ts_policy.parsed = NULL;
  return 0;
}

/* JSON decoder */

typedef struct {
  int consumed;
} json_state;

static int decoder_json_next(ingest_decoder* dec, uint8_t** payload, uint32_t* len, uint64_t* ts_ns) {
  json_state* st = (json_state*)dec->state;
  if (st->consumed) {
    return DECODER_STATUS_EOF;
  }
  size_t cap = 4096;
  size_t used = 0;
  char* buf = (char*)malloc(cap);
  if (!buf) return DECODER_STATUS_ERROR;
  for (;;) {
    size_t got = 0;
    int status = ingest_source_read(dec->source, (uint8_t*)buf + used, cap - used, &got);
    if (status == SOURCE_STATUS_ERROR) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    used += got;
    if (status == SOURCE_STATUS_EOF) {
      break;
    }
    if (used == cap) {
      cap *= 2;
      if (cap > MAX_PAYLOAD_BYTES) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      char* tmp = (char*)realloc(buf, cap);
      if (!tmp) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      buf = tmp;
    }
  }
  st->consumed = 1;
  if (used == 0) {
    free(buf);
    return DECODER_STATUS_EOF;
  }
  uint64_t ts = now_ns();
  const char* parsed = "none";
  for (size_t i = 0; i < sizeof(candidate_fields)/sizeof(candidate_fields[0]); ++i) {
    const char* start;
    size_t value_len;
    int is_str;
    if (find_json_value(buf, candidate_fields[i], &start, &value_len, &is_str) == 0) {
      if (parse_timestamp_field(start, value_len, &ts, &parsed) == 0) {
        set_timestamp_policy(dec, "field", candidate_fields[i], parsed);
        break;
      }
    }
  }
  if (!dec->ts_policy.source) {
    set_timestamp_policy(dec, "now", NULL, "none");
  }
  *payload = (uint8_t*)buf;
  *len = (uint32_t)used;
  *ts_ns = ts;
  return DECODER_STATUS_OK;
}

static void decoder_json_close(ingest_decoder* dec) {
  if (dec->state) {
    free(dec->state);
    dec->state = NULL;
  }
}

static int decoder_json_init(ingest_decoder* dec, const ingest_config* cfg, ingest_source* source) {
  (void)cfg;
  dec->source = source;
  json_state* st = (json_state*)calloc(1, sizeof(json_state));
  if (!st) return -1;
  dec->state = st;
  dec->ts_policy.source = NULL;
  dec->ts_policy.field = NULL;
  dec->ts_policy.parsed = NULL;
  return 0;
}

/* CSV decoder */

typedef struct {
  char** headers;
  size_t columns;
  int ts_index;
  int initialized;
} csv_state;

static void csv_state_free(csv_state* st) {
  if (!st) return;
  for (size_t i = 0; i < st->columns; ++i) {
    free(st->headers[i]);
  }
  free(st->headers);
}

static int split_csv_line(const char* line, size_t len, char*** fields_out, size_t* count_out) {
  size_t cap = 8;
  size_t count = 0;
  char** fields = (char**)malloc(sizeof(char*) * cap);
  if (!fields) return -1;
  size_t i = 0;
  while (i < len) {
    if (count == cap) {
      cap *= 2;
      char** tmp = (char**)realloc(fields, sizeof(char*) * cap);
      if (!tmp) {
        for (size_t k = 0; k < count; ++k) free(fields[k]);
        free(fields);
        return -1;
      }
      fields = tmp;
    }
    size_t start = i;
    int in_quotes = 0;
    if (line[i] == '"') {
      in_quotes = 1;
      start = ++i;
      while (i < len) {
        if (line[i] == '"' && (i + 1 >= len || line[i + 1] != '"')) {
          break;
        }
        if (line[i] == '"' && line[i + 1] == '"') {
          i += 2;
          continue;
        }
        ++i;
      }
    }
    while (i < len && !(in_quotes == 0 && line[i] == ',')) {
      if (in_quotes && line[i] == '"' && (i + 1 >= len || line[i + 1] != '"')) {
        ++i;
        break;
      }
      ++i;
    }
    size_t end = i;
    if (in_quotes && end > start && line[end - 1] == '"') end--;
    size_t field_len = end > start ? end - start : 0;
    char* field = (char*)malloc(field_len + 1);
    if (!field) {
      for (size_t k = 0; k < count; ++k) free(fields[k]);
      free(fields);
      return -1;
    }
    memcpy(field, &line[start], field_len);
    field[field_len] = '\0';
    fields[count++] = field;
    if (i < len && line[i] == ',') ++i;
  }
  *fields_out = fields;
  *count_out = count;
  return 0;
}

static int decoder_csv_init(ingest_decoder* dec, const ingest_config* cfg, ingest_source* source) {
  (void)cfg;
  dec->source = source;
  csv_state* st = (csv_state*)calloc(1, sizeof(csv_state));
  if (!st) return -1;
  dec->state = st;
  set_timestamp_policy(dec, "now", NULL, "none");
  return 0;
}

static int decoder_csv_next(ingest_decoder* dec, uint8_t** payload, uint32_t* len, uint64_t* ts_ns) {
  csv_state* st = dec->state;
  size_t cap = 256;
  size_t used = 0;
  char* buf = malloc(cap);
  if (!buf) return DECODER_STATUS_ERROR;
  int status;
  int newline_seen = 0;
  for (;;) {
    int ch;
    status = ingest_source_getc(dec->source, &ch);
    if (status == SOURCE_STATUS_ERROR) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    if (status == SOURCE_STATUS_EOF) {
      if (used == 0) {
        free(buf);
        return DECODER_STATUS_EOF;
      }
      break;
    }
    if (ch == '\n') {
      newline_seen = 1;
      break;
    }
    if (used + 1 >= cap) {
      cap *= 2;
      if (cap > MAX_PAYLOAD_BYTES) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      char* tmp = (char*)realloc(buf, cap);
      if (!tmp) {
        free(buf);
        return DECODER_STATUS_ERROR;
      }
      buf = tmp;
    }
    buf[used++] = (char)ch;
  }
  if (used > 0 && buf[used - 1] == '\r') used--;
  buf[used] = '\0';
  if (!st->initialized) {
    char** fields = NULL;
    size_t count = 0;
    if (split_csv_line(buf, used, &fields, &count) != 0 || count == 0) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    st->headers = fields;
    st->columns = count;
    st->initialized = 1;
    st->ts_index = -1;
    for (size_t i = 0; i < count; ++i) {
      for (size_t j = 0; j < sizeof(candidate_fields) / sizeof(candidate_fields[0]); ++j) {
        if (equals_ignore_case(fields[i], candidate_fields[j])) {
          st->ts_index = (int)i;
          break;
        }
      }
      if (st->ts_index >= 0) break;
    }
    free(buf);
    return decoder_csv_next(dec, payload, len, ts_ns);
  }
  char** fields = NULL;
  size_t count = 0;
  if (split_csv_line(buf, used, &fields, &count) != 0) {
    size_t stash_len = used + (newline_seen ? 1 : 0);
    dec->pending_raw = (uint8_t*)malloc(stash_len);
    if (dec->pending_raw) {
      memcpy(dec->pending_raw, buf, used);
      if (newline_seen) dec->pending_raw[used] = '\n';
      dec->pending_raw_len = (uint32_t)stash_len;
    }
    free(buf);
    return DECODER_STATUS_MISMATCH;
  }
  if (count != st->columns) {
    for (size_t i = 0; i < count; ++i) free(fields[i]);
    free(fields);
    size_t stash_len = used + (newline_seen ? 1 : 0);
    dec->pending_raw = (uint8_t*)malloc(stash_len);
    if (dec->pending_raw) {
      memcpy(dec->pending_raw, buf, used);
      if (newline_seen) dec->pending_raw[used] = '\n';
      dec->pending_raw_len = (uint32_t)stash_len;
    }
    free(buf);
    return DECODER_STATUS_MISMATCH;
  }
  uint64_t ts = now_ns();
  const char* parsed = "none";
  if (st->ts_index >= 0) {
    const char* ts_val = fields[st->ts_index];
    size_t ts_len = strlen(ts_val);
    if (parse_timestamp_field(ts_val, ts_len, &ts, &parsed) == 0) {
      set_timestamp_policy(dec, "field", st->headers[st->ts_index], parsed);
    }
  }
  for (size_t i = 0; i < count; ++i) free(fields[i]);
  free(fields);
  *payload = (uint8_t*)buf;
  *len = (uint32_t)used;
  *ts_ns = ts;
  return DECODER_STATUS_OK;
}

static void decoder_csv_close(ingest_decoder* dec) {
  csv_state* st = (csv_state*)dec->state;
  csv_state_free(st);
  free(st);
}

/* len4 decoder */

typedef struct {
  uint8_t header[4];
  size_t header_used;
} len4_state;

static int decoder_len4_init(ingest_decoder* dec, const ingest_config* cfg, ingest_source* source) {
  (void)cfg;
  dec->source = source;
  len4_state* st = (len4_state*)calloc(1, sizeof(len4_state));
  if (!st) return -1;
  dec->state = st;
  set_timestamp_policy(dec, "now", NULL, "none");
  return 0;
}

static int decoder_len4_next(ingest_decoder* dec, uint8_t** payload, uint32_t* len, uint64_t* ts_ns) {
  len4_state* st = (len4_state*)dec->state;
  while (st->header_used < 4) {
    size_t got = 0;
    int status = ingest_source_read(dec->source, st->header + st->header_used, 4 - st->header_used, &got);
    if (status == SOURCE_STATUS_ERROR) {
      return DECODER_STATUS_ERROR;
    }
    if (status == SOURCE_STATUS_EOF && got == 0) {
      return DECODER_STATUS_EOF;
    }
    st->header_used += got;
  }
  uint32_t len_le = (uint32_t)st->header[0] | ((uint32_t)st->header[1] << 8) |
                    ((uint32_t)st->header[2] << 16) | ((uint32_t)st->header[3] << 24);
  if (len_le > MAX_PAYLOAD_BYTES) {
    return DECODER_STATUS_ERROR;
  }
  uint8_t* buf = (uint8_t*)malloc(len_le);
  if (!buf) return DECODER_STATUS_ERROR;
  size_t off = 0;
  while (off < len_le) {
    size_t got = 0;
    int status = ingest_source_read(dec->source, buf + off, len_le - off, &got);
    if (status == SOURCE_STATUS_ERROR) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    if (status == SOURCE_STATUS_EOF && got == 0) {
      free(buf);
      return DECODER_STATUS_ERROR;
    }
    off += got;
  }
  st->header_used = 0;
  *payload = buf;
  *len = len_le;
  *ts_ns = now_ns();
  return DECODER_STATUS_OK;
}

static void decoder_len4_close(ingest_decoder* dec) {
  free(dec->state);
}

/* raw decoder */

typedef struct {
  int dummy;
} raw_state;

static int decoder_raw_init(ingest_decoder* dec, const ingest_config* cfg, ingest_source* source) {
  (void)cfg;
  dec->source = source;
  set_timestamp_policy(dec, "now", NULL, "none");
  return 0;
}

static int decoder_raw_next(ingest_decoder* dec, uint8_t** payload, uint32_t* len, uint64_t* ts_ns) {
  size_t cap = RAW_CHUNK_BYTES;
  uint8_t* buf = (uint8_t*)malloc(cap);
  if (!buf) return DECODER_STATUS_ERROR;
  size_t got = 0;
  int status = ingest_source_read(dec->source, buf, cap, &got);
  if (status == SOURCE_STATUS_ERROR) {
    free(buf);
    return DECODER_STATUS_ERROR;
  }
  if (got == 0) {
    free(buf);
    return DECODER_STATUS_EOF;
  }
  *payload = buf;
  *len = (uint32_t)got;
  *ts_ns = now_ns();
  return DECODER_STATUS_OK;
}

static void decoder_raw_close(ingest_decoder* dec) {
  (void)dec;
}

static int sniff_auto(ingest_source* src, int* out_fmt, uint8_t** out_buf, size_t* out_len) {
  const size_t PEEK = 2048;
  uint8_t* buf = malloc(PEEK);
  if (!buf) return -1;

  size_t got = 0;
  while (got < PEEK) {
    size_t n = 0;
    int st = ingest_source_read(src, buf + got, PEEK - got, &n);
    if (st == SOURCE_STATUS_ERROR) { free(buf); return -1; }
    got += n;
    if (st == SOURCE_STATUS_EOF || n == 0) break;
  }
  if (got == 0) {
    *out_fmt = FMT_RAW;
    *out_buf = buf; *out_len = 0;
    return 0;
  }

  /* heuristics */
  const char* s = (const char*)buf;
  size_t n = got;

  /* ndjson-ish: multiple newlines and many { or [ at line starts */
  {
    int braces = 0, lines = 0;
    int at_line_start = 1;
    for (size_t i = 0; i < n; i++) {
      char c = s[i];
      if (at_line_start && (c == '{' || c == '[')) braces++;
      if (c == '\n') { lines++; at_line_start = 1; } else at_line_start = 0;
      if (lines >= 3 && braces >= 2) { *out_fmt = FMT_NDJSON; *out_buf = buf; *out_len = got; return 0; }
    }
  }

  /* csv-ish: commas on multiple lines, few braces/brackets */
  {
    int commas = 0, newlines = 0, braces = 0;
    for (size_t i = 0; i < n; i++) {
      if (s[i] == ',') commas++;
      if (s[i] == '\n') newlines++;
      if (s[i] == '{' || s[i] == '[') braces++;
    }
    if (newlines >= 2 && commas >= 3 && braces == 0) { *out_fmt = FMT_CSV; *out_buf = buf; *out_len = got; return 0; }
  }

  /* lines: several newlines and no obvious binary */
  {
    int newlines = 0, binaryish = 0;
    for (size_t i = 0; i < n; i++) {
      unsigned char c = (unsigned char)s[i];
      if (c == '\n') newlines++;
      if ((c < 9 || (c > 13 && c < 32)) && c != 0) binaryish++;
    }
    if (newlines >= 2 && binaryish == 0) { *out_fmt = FMT_LINES; *out_buf = buf; *out_len = got; return 0; }
  }

  /* len4: plausible 32-bit little-endian length in first 4 bytes */
  if (n >= 4) {
    uint32_t len = (uint32_t)(unsigned char)s[0] |
                   (uint32_t)(unsigned char)s[1] << 8 |
                   (uint32_t)(unsigned char)s[2] << 16 |
                   (uint32_t)(unsigned char)s[3] << 24;
    if (len > 0 && len < MAX_PAYLOAD_BYTES) { *out_fmt = FMT_LEN4; *out_buf = buf; *out_len = got; return 0; }
  }

  /* fallback raw */
  *out_fmt = FMT_RAW;
  *out_buf = buf; *out_len = got;
  return 0;
}

/* factory + helpers */

int make_decoder(const ingest_config* cfg, ingest_source* source, ingest_decoder* out) {
  memset(out, 0, sizeof(*out));
  out->cfg = cfg;
  out->source = source;

  int fmt = cfg->fmt;
  uint8_t* peek_buf = NULL;
  size_t peek_len = 0;

  if (fmt == FMT_AUTO) {
    if (sniff_auto(source, &fmt, &peek_buf, &peek_len) != 0) {
      return -1;
    }
  }

  /* remember final choice for META */
  out->resolved_fmt = fmt;

  /* wire function table */
  switch (fmt) {
    case FMT_LINES:
      out->init = decoder_lines_init;
      out->next = decoder_lines_next;
      out->close = decoder_lines_close;
      break;
    case FMT_NDJSON:
      out->init = decoder_lines_json_init;
      out->next = decoder_lines_json_next;
      out->close = decoder_lines_json_close;
      break;
    case FMT_JSON: {
      out->init = decoder_json_init;
      out->next = decoder_json_next;
      out->close = decoder_json_close;
      break;
    }
    case FMT_CSV:
      out->init = decoder_csv_init;
      out->next = decoder_csv_next;
      out->close = decoder_csv_close;
      break;
    case FMT_LEN4:
      out->init = decoder_len4_init;
      out->next = decoder_len4_next;
      out->close = decoder_len4_close;
      break;
    case FMT_RAW:
    default:
      out->init = decoder_raw_init;
      out->next = decoder_raw_next;
      out->close = decoder_raw_close;
      break;
  }

  /* initialize selected decoder */
  if (out->init(out, cfg, source) != 0) {
    if (peek_buf) free(peek_buf);
    return -1;
  }

  /* give the sniffed bytes back so the decoder sees them */
  if (peek_buf && peek_len) {
    ingest_source_unread(source, peek_buf, peek_len);
    free(peek_buf);
  }

  return 0;
}

void destroy_decoder(ingest_decoder* d) {
  if (!d) return;
  if (d->close) d->close(d);
  if (d->pending_raw) { free(d->pending_raw); d->pending_raw = NULL; d->pending_raw_len = 0; }
  memset(d, 0, sizeof(*d));
}