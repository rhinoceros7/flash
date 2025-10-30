#include "frf.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#if defined(_WIN32)
  #include <io.h> // _commit, _fileno
  #define fsync _commit
#else
  #include <unistd.h> // fsync, fileno
#endif

static int write_exact(FILE* fp, const void* p, size_t n) {
    return fwrite(p, 1, n, fp) == n ? 0 : -1;
}
static int read_exact(FILE* fp, void* p, size_t n) {
    return fread(p, 1, n, fp) == n ? 0 : -1;
}

// Fixed little endian helpers (to make sure files are always read in LE)
static void u32_to_le(uint32_t v, unsigned char out[4]) {
    out[0] = (unsigned char)(v);
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}
static void u64_to_le(uint64_t v, unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) out[i] = (unsigned char)(v >> (8*i));
}
static uint32_t le_to_u32(const unsigned char in[4]) {
    return ((uint32_t)in[0]) | ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}
static uint64_t le_to_u64(const unsigned char in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)in[i]) << (8*i);
    return v;
}

int frf_open(const char* path, const char* mode, frf_handle_t* out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    FILE* fp = fopen(path, mode);
    if (!fp) return -1;
    out->fp = fp;
    out->is_writer = (mode[0] == 'w' || mode[0] == 'a');
    return 0;
}

void frf_close(frf_handle_t* h) {
    if (!h || !h->fp) return;
    fflush(h->fp);
    int fd = fileno(h->fp);
    if (fd >= 0) fsync(fd);
    fclose(h->fp);
    h->fp = NULL;
}

int frf_write_header_if_new(frf_handle_t* h, uint64_t created_unix_ns) {
    if (!h || !h->fp || !h->is_writer) return -1;

    // Determine true file size
    long save = ftell(h->fp);
    if (save < 0) save = 0;
    if (fseek(h->fp, 0, SEEK_END) != 0) return -1;
    long endpos = ftell(h->fp);
    if (endpos < 0) return -1;

    if (endpos > 0) {
        // File is not empty: ensure we are at end for appends and return
        (void)fseek(h->fp, 0, SEEK_END);
        return 0;
    }

    // New/empty file: write magic + header at the beginning
    if (fseek(h->fp, 0, SEEK_SET) != 0) return -1;

    if (write_exact(h->fp, FRF_MAGIC, FRF_MAGIC_LEN)) return -1;

    frf_file_header_t fh = {0};
    fh.flags = 0;
    fh.created_unix_ns = created_unix_ns;
    if (write_exact(h->fp, &fh, sizeof(fh))) return -1;

    fflush(h->fp);
    int fd = fileno(h->fp);
    if (fd >= 0) fsync(fd);

    // Position at end for subsequent appends
    (void)fseek(h->fp, 0, SEEK_END);
    return 0;
}


int frf_append_record(
    frf_handle_t* h, uint32_t type, uint64_t ts_unix_ns,
    const void* payload, uint32_t payload_len
    ) {
    if (!h || !h->fp || !h->is_writer) return -1;

    frf_record_header_t rh;
    rh.length = payload_len;
    rh.type   = type;
    rh.ts_unix_ns = ts_unix_ns;

    // Build a contiguous buffer for CRC over (type || ts || payload)
    size_t total = sizeof(rh.type) + sizeof(rh.ts_unix_ns) + payload_len;
    unsigned char* buf = (unsigned char*)malloc(total);
    if (!buf) return -1;
    memcpy(buf, &rh.type, sizeof(rh.type));
    memcpy(buf + sizeof(rh.type), &rh.ts_unix_ns, sizeof(rh.ts_unix_ns));
    if (payload_len && payload)
        memcpy(buf + sizeof(rh.type) + sizeof(rh.ts_unix_ns), payload, payload_len);
    rh.crc32 = frf_crc32(buf, total);
    free(buf);

    unsigned char hdr[20];
    u32_to_le(rh.length, hdr + 0);
    u32_to_le(rh.type, hdr + 4);
    u64_to_le(rh.ts_unix_ns, hdr + 8);
    u32_to_le(rh.crc32, hdr + 16);

    if (write_exact(h->fp, hdr, sizeof(hdr))) return -1;
    if (payload_len && payload)
        if (write_exact(h->fp, payload, payload_len)) return -1;

    // Caller decides fsync cadence
    fflush(h->fp);
    return 0;
}

int frf_read_and_verify_header(frf_handle_t* h, frf_file_header_t* out) {
    if (!h || !h->fp) return -1;
    char magic[FRF_MAGIC_LEN];
    if (read_exact(h->fp, magic, FRF_MAGIC_LEN)) return -1;
    if (memcmp(magic, FRF_MAGIC, FRF_MAGIC_LEN) != 0) return -2;
    if (read_exact(h->fp, out, sizeof(*out))) return -1;
    return 0;
}

int frf_next_record(
    frf_handle_t* h, frf_record_header_t* hdr, void* payload_buf,
    uint32_t buf_cap, uint32_t* out_len
    ) {
    if (!h || !h->fp) return -1;

    unsigned char raw[20];
    size_t n = fread(raw, 1, sizeof(raw), h->fp);
    if (n == 0) return 1; // clean EOF
    if (n != sizeof(raw)) return -2; // truncated header

    hdr->length = le_to_u32(raw + 0);
    hdr->type = le_to_u32(raw + 4);
    hdr->ts_unix_ns = le_to_u64(raw + 8);
    hdr->crc32 = le_to_u32(raw + 16);

    if (hdr->length > buf_cap) return -3;

    if (hdr->length > 0) {
        if (read_exact(h->fp, payload_buf, hdr->length)) return -4;
    }

    // Verify CRC over (type || ts || payload) in LE form
    size_t total = 4 + 8 + hdr->length;
    unsigned char* crcbuf = (unsigned char*)malloc(total);
    if (!crcbuf) return -5;
    u32_to_le(hdr->type, crcbuf + 0);
    u64_to_le(hdr->ts_unix_ns, crcbuf + 4);
    if (hdr->length > 0) memcpy(crcbuf + 12, payload_buf, hdr->length);

    uint32_t crc = frf_crc32(crcbuf, total);
    free(crcbuf);

    if (crc != hdr->crc32) return -6; // bad CRC

    if (out_len) *out_len = hdr->length;
    return 0;
}
