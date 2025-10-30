#include "frf.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

static void hex_dump(const unsigned char* p, uint32_t n, uint32_t max){
    uint32_t m = n < max ? n : max;
    for (uint32_t i=0;i<m;i++){
        printf("%02X", p[i]);
        if (i+1<m) printf(" ");
    }
    if (n>max) printf(" ...");
}

int main(int argc, char** argv){
    if (argc < 2){
        fprintf(stderr, "Usage: %s <file.flsh> [dump_bytes]\n", argv[0]);
        return 2;
    }
    uint32_t dump_bytes = (argc>=3) ? (uint32_t)strtoul(argv[2], NULL, 10) : 64;

    frf_handle_t h;
    if (frf_open(argv[1], "rb", &h) != 0){ perror("open"); return 1; }

    frf_file_header_t fh;
    int rc = frf_read_and_verify_header(&h, &fh);
    if (rc){ fprintf(stderr, "Invalid header (rc=%d)\n", rc); frf_close(&h); return 1; }
    printf("FLSH created_ns=%" PRIu64 "\n", fh.created_unix_ns);

    unsigned char buf[65536];
    frf_record_header_t rh;
    uint32_t nread = 0;
    size_t count = 0;

    while ((rc = frf_next_record(&h, &rh, buf, sizeof(buf), &nread)) == 0){
        printf("#%zu type=%u ts=%" PRIu64 " len=%u payload[0:%u]=",
               ++count, rh.type, rh.ts_unix_ns, rh.length, dump_bytes);
        hex_dump(buf, nread, dump_bytes);
        printf("\n");
    }
    if (rc != 1) fprintf(stderr, "Stopped with rc=%d (possibly truncated)\n", rc);

    frf_close(&h);
    return 0;
}
