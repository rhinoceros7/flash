// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#include "ingest_source.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #ifdef _MSC_VER
  #pragma comment(lib, "Ws2_32.lib")
  #endif
  #define popen  _popen
  #define pclose _pclose
#else
  #include <dirent.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <unistd.h>
#endif

/* internal impl kinds */
typedef enum {
  IMPL_FILEFP, /* stdin / file / dir-file */
  IMPL_SOCKET, /* tcp/udp */
  IMPL_POPEN /* curl/websocat pipe */
} impl_kind;

struct ingest_source {
  int kind; /* cfg->src_kind */
  char detail[512]; /* human-readable detail */
  const ingest_config* cfg;

  /* pushback buffer for unread bytes */
  uint8_t* pushback;
  size_t   pushback_len;

#ifdef _WIN32
  int wsa_active;
#endif

  impl_kind impl;
  union {
    struct { FILE* fp; char current_path[512]; } file;   /* stdin/file/dir current */
#ifndef _WIN32
    struct { char** entries; size_t count; size_t index; char base_path[512]; FILE* current_fp; } dir;
#endif
    struct {
#ifdef _WIN32
      SOCKET fd;
#else
      int fd;
#endif
      int socktype;
    } sock; /* tcp/udp */
    struct { FILE* pipe; } popen; /* curl/websocat */
  } u;
};

/* pushback helpers */

static void prepend_pushback(ingest_source* src, const uint8_t* data, size_t len) {
  if (!len) return;
  uint8_t* buf = (uint8_t*)malloc(len + src->pushback_len);
  if (!buf) return;
  memcpy(buf, data, len);
  if (src->pushback && src->pushback_len) {
    memcpy(buf + len, src->pushback, src->pushback_len);
    free(src->pushback);
  }
  src->pushback = buf;
  src->pushback_len += len;
}

static size_t pop_pushback(ingest_source* src, uint8_t* dst, size_t cap) {
  if (!src->pushback || !src->pushback_len) return 0;
  size_t take = src->pushback_len < cap ? src->pushback_len : cap;
  memcpy(dst, src->pushback, take);
  if (take < src->pushback_len) {
    memmove(src->pushback, src->pushback + take, src->pushback_len - take);
  } else {
    free(src->pushback);
    src->pushback = NULL;
  }
  src->pushback_len -= take;
  return take;
}

/* basic file/stdin */

static int open_stdin(ingest_source* src) {
  src->impl = IMPL_FILEFP;
  src->u.file.fp = stdin;
  snprintf(src->detail, sizeof(src->detail), "stdin");
  return 0;
}

static int open_file(ingest_source* src, const char* path, char* err, size_t err_cap) {
  FILE* fp = fopen(path, "rb");
  if (!fp) {
    if (err && err_cap) snprintf(err, err_cap, "failed to open %s: %s", path, strerror(errno));
    return -1;
  }
  src->impl = IMPL_FILEFP;
  src->u.file.fp = fp;
  strncpy(src->u.file.current_path, path, sizeof(src->u.file.current_path)-1);
  src->u.file.current_path[sizeof(src->u.file.current_path)-1] = '\0';
  snprintf(src->detail, sizeof(src->detail), "%s", path);
  return 0;
}

/* directory (posix) */
#ifndef _WIN32
static int compare_strings(const void* a, const void* b) {
  const char* const* sa = (const char* const*)a;
  const char* const* sb = (const char* const*)b;
  return strcmp(*sa, *sb);
}

static int open_dir(ingest_source* src, const char* path, char* err, size_t err_cap) {
  DIR* dir = opendir(path);
  if (!dir) {
    if (err && err_cap) snprintf(err, err_cap, "failed to open dir %s: %s", path, strerror(errno));
    return -1;
  }
  struct dirent* ent;
  size_t cap = 16, count = 0;
  char** entries = (char**)malloc(sizeof(char*) * cap);
  if (!entries) { closedir(dir); if (err&&err_cap) snprintf(err, err_cap, "out of memory"); return -1; }
  while ((ent = readdir(dir)) != NULL) {
    if (!strcmp(ent->d_name,".") || !strcmp(ent->d_name,"..")) continue;
    if (count == cap) {
      cap *= 2;
      char** tmp = (char**)realloc(entries, sizeof(char*) * cap);
      if (!tmp) { for (size_t i=0;i<count;++i) free(entries[i]); free(entries); closedir(dir); if (err&&err_cap) snprintf(err, err_cap, "out of memory"); return -1; }
      entries = tmp;
    }
    entries[count] = strdup(ent->d_name);
    if (!entries[count]) { for (size_t i=0;i<count;++i) free(entries[i]); free(entries); closedir(dir); if (err&&err_cap) snprintf(err, err_cap, "out of memory"); return -1; }
    count++;
  }
  closedir(dir);
  qsort(entries, count, sizeof(char*), compare_strings);
  src->impl = IMPL_FILEFP; /* we’ll read each file via FILE* */
  src->u.dir.entries = entries;
  src->u.dir.count = count;
  src->u.dir.index = 0;
  strncpy(src->u.dir.base_path, path, sizeof(src->u.dir.base_path)-1);
  src->u.dir.current_fp = NULL;
  snprintf(src->detail, sizeof(src->detail), "%s", path);
  return 0;
}

static int dir_open_next_file(ingest_source* src) {
  if (src->u.dir.index >= src->u.dir.count) return SOURCE_STATUS_EOF;
  const char* name = src->u.dir.entries[src->u.dir.index++];
  char full_path[1024];
  snprintf(full_path, sizeof(full_path), "%s/%s", src->u.dir.base_path, name);
  FILE* fp = fopen(full_path, "rb");
  if (!fp) return -1;
  src->u.dir.current_fp = fp;
  snprintf(src->detail, sizeof(src->detail), "%s", full_path);
  return 0;
}
#endif

/* sockets */
#ifndef _WIN32
static int open_socket_stream(ingest_source* src, const char* hostport, int type, char* err, size_t err_cap) {
  const char* port = NULL;
  char host_buf[128];
  const char* host = NULL;

  if (!hostport || !*hostport) { if (err&&err_cap) snprintf(err, err_cap, "empty host/port"); return -1; }

  if (hostport[0] == ':') { port = hostport + 1; host = NULL; }
  else {
    const char* colon = strrchr(hostport, ':');
    if (!colon) { if (err&&err_cap) snprintf(err, err_cap, "expected :PORT or HOST:PORT"); return -1; }
    size_t hlen = (size_t)(colon - hostport);
    if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf)-1;
    memcpy(host_buf, hostport, hlen); host_buf[hlen] = '\0';
    host = host_buf; port = colon + 1;
  }

  struct addrinfo hints; memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC; hints.ai_socktype = type; hints.ai_flags = 0;

  struct addrinfo* res = NULL;
  int rc = getaddrinfo(host, port, &hints, &res);
  if (rc != 0 || !res) { if (err&&err_cap) snprintf(err, err_cap, "getaddrinfo failed"); return -1; }

  int fd = -1;
  for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
    fd = (int)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    if (type == SOCK_DGRAM) {
      struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100 * 1000; /* 100ms */
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    if (type == SOCK_STREAM) {
      if (connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) break;
    } else {
      if (bind(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) break;
    }
    close(fd); fd = -1;
  }
  freeaddrinfo(res);

  if (fd < 0) { if (err&&err_cap) snprintf(err, err_cap, "%s open failed", type==SOCK_STREAM?"tcp":"udp"); return -1; }

  src->impl = IMPL_SOCKET;
  src->u.sock.fd = fd;
  src->u.sock.socktype = type;
  snprintf(src->detail, sizeof(src->detail), "%s", hostport);
  return 0;
}
#else
static int open_socket_stream_win(ingest_source* src, const char* hostport, int type, char* err, size_t err_cap) {
  const char* port = NULL; char host_buf[128]; const char* host = NULL;
  if (!hostport || !*hostport) { if (err&&err_cap) _snprintf(err, err_cap, "empty host/port"); return -1; }
  if (hostport[0] == ':') { port = hostport + 1; host = NULL; }
  else {
    const char* colon = strrchr(hostport, ':');
    if (!colon) { if (err&&err_cap) _snprintf(err, err_cap, "expected :PORT or HOST:PORT"); return -1; }
    size_t hlen = (size_t)(colon - hostport); if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf)-1;
    memcpy(host_buf, hostport, hlen); host_buf[hlen] = '\0'; host = host_buf; port = colon + 1;
  }
  struct addrinfo hints; memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC; hints.ai_socktype = type; hints.ai_flags = 0;

  struct addrinfo* res = NULL;
  int rc = getaddrinfo(host, port, &hints, &res);
  if (rc != 0 || !res) { if (err&&err_cap) _snprintf(err, err_cap, "getaddrinfo failed"); return -1; }

  SOCKET s = INVALID_SOCKET;
  for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) continue;

    if (type == SOCK_DGRAM) {
      DWORD to_ms = 100;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to_ms, sizeof(to_ms));
    }

    if (type == SOCK_STREAM) {
      if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
    } else {
      if (bind(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
    }
    closesocket(s); s = INVALID_SOCKET;
  }
  freeaddrinfo(res);
  if (s == INVALID_SOCKET) { if (err&&err_cap) _snprintf(err, err_cap, "%s open failed", type==SOCK_STREAM?"tcp":"udp"); return -1; }

  src->impl = IMPL_SOCKET;
  src->u.sock.fd = s;
  src->u.sock.socktype = type;
  _snprintf(src->detail, sizeof(src->detail), "%s", hostport);
  return 0;
}
#endif

/* curl/websocat adapters */

static int open_http_like_via_curl(ingest_source* src, const char* url, int sse_mode, char* err, size_t err_cap) {
  char cmd[1024];
  if (sse_mode) {
    snprintf(cmd, sizeof(cmd),
      "curl --silent --show-error --fail --no-buffer --location --http1.1 --header \"Accept: text/event-stream\" \"%s\"", url);
  } else {
    snprintf(cmd, sizeof(cmd),
      "curl --silent --show-error --fail --no-buffer --location --http1.1 \"%s\"", url);
  }
  FILE* p = popen(cmd, "r");
  if (!p) { if (err&&err_cap) snprintf(err, err_cap, "failed to launch curl for '%s': %s", url, strerror(errno)); return -1; }
  src->impl = IMPL_POPEN;
  src->u.popen.pipe = p;
  strncpy(src->detail, url, sizeof(src->detail)-1);
  return 0;
}

static int open_ws_via_websocat(ingest_source* src, const char* url, char* err, size_t err_cap) {
#ifdef _WIN32
  const char* ws_cmd = "websocat.exe -q -E -t ";
#else
  const char* ws_cmd = "websocat -q -E -t ";
#endif
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "%s \"%s\"", ws_cmd, url);
  FILE* p = popen(cmd, "r");
  if (!p) { if (err&&err_cap) snprintf(err, err_cap, "websocket requires 'websocat' in PATH for now"); return -1; }
  src->impl = IMPL_POPEN;
  src->u.popen.pipe = p;
  strncpy(src->detail, url, sizeof(src->detail)-1);
  return 0;
}

/* API impls */

int ingest_source_open(const ingest_config* cfg, ingest_source** out_source, char* err_msg, size_t err_cap) {
  ingest_source* src = (ingest_source*)calloc(1, sizeof(*src));
  if (!src) { if (err_msg && err_cap) snprintf(err_msg, err_cap, "out of memory"); return -1; }
  src->cfg = cfg;
  src->kind = cfg->src_kind;

#ifdef _WIN32
  src->u.sock.fd = INVALID_SOCKET;
  if (cfg->src_kind == SRC_TCP || cfg->src_kind == SRC_UDP) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
      if (err_msg && err_cap) _snprintf(err_msg, err_cap, "WSAStartup failed");
      free(src);
      return -1;
    }
    src->wsa_active = 1;
  }
#else
  src->u.sock.fd = -1;
#endif

  int rc = -1;
  switch (cfg->src_kind) {
    case SRC_STDIN: rc = open_stdin(src); break;
    case SRC_FILE: rc = open_file(src, cfg->src_detail, err_msg, err_cap); break;
#ifndef _WIN32
    case SRC_DIR: rc = open_dir(src, cfg->src_detail, err_msg, err_cap); break;
    case SRC_TCP: rc = open_socket_stream(src, cfg->src_detail, SOCK_STREAM, err_msg, err_cap); break;
    case SRC_UDP: rc = open_socket_stream(src, cfg->src_detail, SOCK_DGRAM, err_msg, err_cap); break;
#else
    case SRC_DIR: if (err_msg&&err_cap) _snprintf(err_msg, err_cap, "dir source unsupported on Windows"); rc = -1; break;
    case SRC_TCP: rc = open_socket_stream_win(src, cfg->src_detail, SOCK_STREAM, err_msg, err_cap); break;
    case SRC_UDP: rc = open_socket_stream_win(src, cfg->src_detail, SOCK_DGRAM, err_msg, err_cap); break;
#endif
    case SRC_SERIAL:
      if (err_msg&&err_cap) snprintf(err_msg, err_cap, "serial source unsupported");
      rc = -1; break;
    case SRC_HTTP: rc = open_http_like_via_curl(src, cfg->src_detail, 0, err_msg, err_cap); break;
    case SRC_SSE: rc = open_http_like_via_curl(src, cfg->src_detail, 1, err_msg, err_cap); break;
    case SRC_WS: rc = open_ws_via_websocat(src, cfg->src_detail, err_msg, err_cap); break;
    default: {
      if (err_msg && err_cap) {
        snprintf(err_msg, err_cap, "invalid source kind");
      }
      rc = -1;
      break;
    }
  }

  if (rc != 0) { free(src); return -1; }
  *out_source = src;
  return 0;
}

const char* ingest_source_current_detail(ingest_source* src) {
#ifndef _WIN32
  if (src->kind == SRC_DIR && src->u.dir.current_fp == NULL && src->u.dir.index < src->u.dir.count) {
    static char buf[1024];
    snprintf(buf, sizeof(buf), "%s/%s", src->u.dir.base_path, src->u.dir.entries[src->u.dir.index]);
    return buf;
  }
#endif
  return src->detail[0] ? src->detail : "(unknown)";
}

static int read_file(FILE* fp, uint8_t* buf, size_t cap, size_t* out_bytes) {
  size_t n = fread(buf, 1, cap, fp);
  if (n > 0) { *out_bytes = n; return SOURCE_STATUS_OK; }
  if (feof(fp)) return SOURCE_STATUS_EOF;
  return SOURCE_STATUS_ERROR;
}

#ifndef _WIN32
#include <errno.h>
#include <sys/time.h>

/* Use recvfrom for UDP so we always read full datagrams; use recv for TCP. */
static int read_socket(int fd, int type, uint8_t* buf, size_t cap, size_t* out_bytes) {
  for (;;) {
    ssize_t n;
    if (type == SOCK_DGRAM) {
      n = recvfrom(fd, buf, cap, 0, NULL, NULL);
    } else {
      n = recv(fd, buf, cap, 0);
    }

    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        /* No packet yet; tell caller to try again without failing. */
        if (out_bytes) *out_bytes = 0;
        return SOURCE_STATUS_OK;
      }
      return SOURCE_STATUS_ERROR;
    }
    if (n == 0) {
      /* TCP: clean EOF; UDP: ignore zero-length datagrams and retry */
      if (type == SOCK_STREAM) return SOURCE_STATUS_EOF;
      continue;
    }
    if (out_bytes) *out_bytes = (size_t)n;
    return SOURCE_STATUS_OK;
  }
}
#endif
#ifdef _WIN32
/* Windows version using winsock error codes. */
static int read_socket(SOCKET s, int type, uint8_t* buf, size_t cap, size_t* out_bytes) {
  for (;;) {
    int n;
    if (type == SOCK_DGRAM) {
      n = recvfrom(s, (char*)buf, (int)cap, 0, NULL, NULL);
    } else {
      n = recv(s, (char*)buf, (int)cap, 0);
    }

    if (n == SOCKET_ERROR) {
      int e = WSAGetLastError();
      if (e == WSAEINTR) continue;
      if (e == WSAEWOULDBLOCK || e == WSAETIMEDOUT) {
        if (out_bytes) *out_bytes = 0;
        return SOURCE_STATUS_OK; /* “no data yet” is not fatal */
      }
      return SOURCE_STATUS_ERROR;
    }
    if (n == 0) {
      if (type == SOCK_STREAM) return SOURCE_STATUS_EOF;
      /* UDP zero-len datagram: ignore & retry */
      continue;
    }
    if (out_bytes) *out_bytes = (size_t)n;
    return SOURCE_STATUS_OK;
  }
}
#endif

int ingest_source_read(ingest_source* src, uint8_t* buf, size_t cap, size_t* out_bytes) {
  if (!cap) { if (out_bytes) *out_bytes = 0; return SOURCE_STATUS_OK; }

  size_t taken = pop_pushback(src, buf, cap);
  if (taken) { if (out_bytes) *out_bytes = taken; return SOURCE_STATUS_OK; }

  switch (src->impl) {
    case IMPL_FILEFP: {
#ifndef _WIN32
      if (src->kind == SRC_DIR) {
        if (!src->u.dir.current_fp) {
          int rc = dir_open_next_file(src);
          if (rc == SOURCE_STATUS_EOF) return SOURCE_STATUS_EOF;
          else if (rc != 0) return SOURCE_STATUS_ERROR;
        }
        int st = read_file(src->u.dir.current_fp, buf, cap, out_bytes);
        if (st == SOURCE_STATUS_EOF) {
          fclose(src->u.dir.current_fp); src->u.dir.current_fp = NULL;
          return ingest_source_read(src, buf, cap, out_bytes);
        }
        return st;
      }
#endif
      return read_file(src->u.file.fp, buf, cap, out_bytes);
    }
    case IMPL_SOCKET:
#ifdef _WIN32
      return read_socket(src->u.sock.fd, src->u.sock.socktype, buf, cap, out_bytes);
#else
      return read_socket(src->u.sock.fd, src->u.sock.socktype, buf, cap, out_bytes);
#endif
    case IMPL_POPEN: {
      size_t n = fread(buf, 1, cap, src->u.popen.pipe);
      if (n > 0) { if (out_bytes) *out_bytes = n; return SOURCE_STATUS_OK; }
      if (feof(src->u.popen.pipe)) return SOURCE_STATUS_EOF;
      return SOURCE_STATUS_ERROR;
    }
    default:
      return SOURCE_STATUS_ERROR;
  }
}

int ingest_source_getc(ingest_source* src, int* out_ch) {
  for (;;) {
    /* Special handling for UDP: read a whole datagram and push back the tail. */
    if (src->impl == IMPL_SOCKET
#ifdef _WIN32
        && src->u.sock.socktype == SOCK_DGRAM
#else
        && src->u.sock.socktype == SOCK_DGRAM
#endif
    ) {
      /* First try pushback (may contain the remainder of a prior datagram). */
      uint8_t ch_pb;
      size_t took = pop_pushback(src, &ch_pb, 1);
      if (took == 1) { *out_ch = ch_pb; return SOURCE_STATUS_OK; }

      /* Pull a full datagram, then return the first byte and unread the rest. */
      uint8_t pkt[65536];
      size_t n = 0;
      int st = ingest_source_read(src, pkt, sizeof(pkt), &n);
      if (st == SOURCE_STATUS_OK && n > 0) {
        *out_ch = pkt[0];
        if (n > 1) ingest_source_unread(src, pkt + 1, n - 1);
        return SOURCE_STATUS_OK;
      }
      if (st == SOURCE_STATUS_OK && n == 0) continue; /* no data yet */
      if (st == SOURCE_STATUS_EOF) return SOURCE_STATUS_EOF;
      return SOURCE_STATUS_ERROR;
    }

    /* Default (file/pipe/TCP): byte-at-a-time is fine. */
    uint8_t ch;
    size_t got = 0;
    int st = ingest_source_read(src, &ch, 1, &got);
    if (st == SOURCE_STATUS_OK && got == 1) { *out_ch = ch; return SOURCE_STATUS_OK; }
    if (st == SOURCE_STATUS_OK && got == 0)  { continue; } /* tolerate spurious 0-byte reads */
    if (st == SOURCE_STATUS_EOF) return SOURCE_STATUS_EOF;
    return SOURCE_STATUS_ERROR;
  }
}

int ingest_source_unread(ingest_source* src, const uint8_t* data, size_t len) {
  prepend_pushback(src, data, len);
  return 0;
}

int ingest_source_close(ingest_source* src) {
  if (!src) return 0;
  int status = 0;

  if (src->pushback) { free(src->pushback); src->pushback = NULL; src->pushback_len = 0; }

  switch (src->impl) {
    case IMPL_FILEFP:
#ifndef _WIN32
      if (src->kind == SRC_DIR) {
        if (src->u.dir.current_fp) fclose(src->u.dir.current_fp);
        if (src->u.dir.entries) {
          for (size_t i = 0; i < src->u.dir.count; ++i) free(src->u.dir.entries[i]);
          free(src->u.dir.entries);
        }
      } else
#endif
      {
        if (src->u.file.fp && src->u.file.fp != stdin) fclose(src->u.file.fp);
      }
      break;

    case IMPL_SOCKET:
#ifndef _WIN32
      if (src->u.sock.fd >= 0) { close(src->u.sock.fd); src->u.sock.fd = -1; }
#else
      if (src->u.sock.fd != INVALID_SOCKET) { closesocket(src->u.sock.fd); src->u.sock.fd = INVALID_SOCKET; }
      if (src->wsa_active) { WSACleanup(); src->wsa_active = 0; }
#endif
      break;

    case IMPL_POPEN:
      if (src->u.popen.pipe) {
        int rc = pclose(src->u.popen.pipe);
        if (rc != 0) status = rc ? rc : 1;
      }
      break;

    default: break;
  }

  free(src);
  return status;
}
