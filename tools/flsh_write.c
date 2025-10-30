#include "frf.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
  #include <windows.h>
  static uint64_t now_ns(void){
      FILETIME ft;
      GetSystemTimePreciseAsFileTime(&ft);
      // FILETIME = 100-ns since 1601-01-01; convert to Unix ns
      uint64_t t100 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
      const uint64_t EPOCH_DIFF_100NS = 11644473600ull * 10000000ull;
      uint64_t unix100 = (t100 >= EPOCH_DIFF_100NS) ? (t100 - EPOCH_DIFF_100NS) : 0;
      return unix100 * 100ull;
  }
#else
  #include <time.h>
  static uint64_t now_ns(void){
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      return (uint64_t)ts.tv_sec*1000000000ull + (uint64_t)ts.tv_nsec;
  }
#endif

static void usage(const char* p){
    fprintf(stderr,
      "Usage:\n"
      "  %s <file.flsh> <type:u32> [payload_file|-] [ts_ns]\n"
      "Examples:\n"
      "  %s log.flsh 100 payload.bin\n"
      "  echo -n hello | %s log.flsh 7 -\n", p, p, p);
}

static int read_all(const char* path, unsigned char** out, uint32_t* out_len){
    *out = NULL; *out_len = 0;
    FILE* f = (path && strcmp(path,"-")==0) ? stdin : fopen(path, "rb");
    if (!f){
        if (path) perror("open payload");
        return 0; // payload is optional
    }
    if (f == stdin){
        size_t cap = 4096, len = 0;
        unsigned char* buf = (unsigned char*)malloc(cap);
        if (!buf) return -1;
        size_t n;
        while ((n = fread(buf+len,1,cap-len,stdin)) > 0){
            len += n;
            if (len == cap){
                cap *= 2;
                unsigned char* nb = (unsigned char*)realloc(buf, cap);
                if (!nb){ free(buf); return -1; }
                buf = nb;
            }
        }
        *out = buf; *out_len = (uint32_t)len;
        return 0;
    }

    if (fseek(f, 0, SEEK_END)) { perror("fseek"); fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { perror("ftell"); fclose(f); return -1; }
    rewind(f);
    unsigned char* buf = (unsigned char*)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { perror("fread"); free(buf); fclose(f); return -1; }
    fclose(f);
    *out = buf; *out_len = (uint32_t)sz;
    return 0;
}

int main(int argc, char** argv){
    if (argc < 3){ usage(argv[0]); return 2; }
    const char* path = argv[1];
    uint32_t type = (uint32_t)strtoul(argv[2], NULL, 10);
    const char* payload_path = (argc >= 4 ? argv[3] : NULL);
    uint64_t ts = (argc >= 5 ? strtoull(argv[4], NULL, 10) : now_ns());

    unsigned char* payload = NULL;
    uint32_t payload_len = 0;
    if (payload_path){
        if (read_all(payload_path, &payload, &payload_len) != 0){
            fprintf(stderr, "failed to read payload\n");
            return 1;
        }
    }

    frf_handle_t h;
    if (frf_open(path, "ab+", &h) != 0){ perror("open"); free(payload); return 1; }
    if (frf_write_header_if_new(&h, now_ns()) != 0){
        fprintf(stderr, "failed to write header\n");
        frf_close(&h); free(payload); return 1;
    }
    if (frf_append_record(&h, type, ts, payload, payload_len) != 0){
        fprintf(stderr, "append failed\n");
        frf_close(&h); free(payload); return 1;
    }
    frf_close(&h);
    free(payload);
    return 0;
}
