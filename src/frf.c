#include "frf.h"
#include "blake3.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#if defined(_WIN32)
  #include <io.h> // _commit, _fileno
  #define fsync _commit
#else
  #include <unistd.h> // fsync, fileno
#endif

static int frf_get_fileno(FILE* fp) {
#if defined(_WIN32)
    return _fileno(fp);
#else
    return fileno(fp);
#endif
}

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

static void blake3_hash_bytes(const unsigned char* data, size_t len,
                              unsigned char out[32]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, len);
    blake3_hasher_finalize(&hasher, out, 32);
}

static void compute_header_hash(frf_handle_t* h,
                                const unsigned char header_bytes[16]) {
    memcpy(h->header_bytes, header_bytes, 16);
    h->header_bytes_valid = true;
    blake3_hash_bytes(header_bytes, 16, h->header_hash);
}

static void compute_frame_hash(const unsigned char header_bytes[FRF_RECORD_HEADER_BYTES],
                               const unsigned char* payload, uint32_t payload_len,
                               const unsigned char prev_hash[32],
                               unsigned char out_hash[32]) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, header_bytes, FRF_RECORD_HEADER_BYTES);
    if (payload_len && payload) {
        blake3_hasher_update(&hasher, payload, payload_len);
    }
    blake3_hasher_update(&hasher, prev_hash, 32);
    blake3_hasher_finalize(&hasher, out_hash, 32);
}

static int prepare_writer_chain(frf_handle_t* h);

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
    int fd = frf_get_fileno(h->fp);
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

    // On a new/empty file: write magic + LE-packed 16-byte header
    if (fseek(h->fp, 0, SEEK_SET) != 0) return -1;

    if (write_exact(h->fp, FRF_MAGIC, FRF_MAGIC_LEN)) return -1;

    // Pack header in LE: [0..3]=flags(u32), [4..11]=created(u64), [12..15]=reserved(u32)
    unsigned char header_bytes[16];
    u32_to_le(0, header_bytes + 0); // flags
    u64_to_le(created_unix_ns, header_bytes + 4); // created_unix_ns
    u32_to_le(0, header_bytes + 12); // reserved

    if (write_exact(h->fp, header_bytes, sizeof header_bytes)) return -1;

    // Anchor chain on the exact serialized bytes
    compute_header_hash(h, header_bytes);
    memcpy(h->prev_hash, h->header_hash, 32);
    h->prev_hash_valid = true;
    h->next_seq_no = 0;

    fflush(h->fp);
    int fd = frf_get_fileno(h->fp);
    if (fd >= 0) fsync(fd);

    // Position at end for subsequent appends
    (void)fseek(h->fp, 0, SEEK_END);
    return 0;
}

static int prepare_writer_chain(frf_handle_t* h) {
    if (!h || !h->fp) return -1;
    if (h->prev_hash_valid && h->header_bytes_valid) return 0;

    long cur = ftell(h->fp);
    if (cur < 0) return -1;
    if (fseek(h->fp, 0, SEEK_SET) != 0) return -1;

    unsigned char magic[FRF_MAGIC_LEN];
    if (read_exact(h->fp, magic, FRF_MAGIC_LEN)) {
        (void)fseek(h->fp, cur, SEEK_SET);
        return -1;
    }
    if (memcmp(magic, FRF_MAGIC, FRF_MAGIC_LEN) != 0) {
        (void)fseek(h->fp, cur, SEEK_SET);
        return -1;
    }

    unsigned char header_raw[16];
    if (read_exact(h->fp, header_raw, sizeof(header_raw))) {
        (void)fseek(h->fp, cur, SEEK_SET);
        return -1;
    }

    compute_header_hash(h, header_raw);
    memcpy(h->prev_hash, h->header_hash, 32);
    h->prev_hash_valid = true;
    h->next_seq_no = 0;

    unsigned char* payload = NULL;
    unsigned char chain_ext[FRF_CHAIN_BYTES];
    unsigned char frame_hash[32];

    for (;;) {
        unsigned char hdr_bytes[FRF_RECORD_HEADER_BYTES];
        size_t n = fread(hdr_bytes, 1, sizeof(hdr_bytes), h->fp);
        if (n == 0) break;
        if (n != sizeof(hdr_bytes)) {
            free(payload);
            (void)fseek(h->fp, cur, SEEK_SET);
            return -1;
        }

        uint32_t length = le_to_u32(hdr_bytes + 0);
        if (length > 0) {
            payload = (unsigned char*)realloc(payload, length);
            if (!payload) {
                (void)fseek(h->fp, cur, SEEK_SET);
                return -1;
            }
            if (read_exact(h->fp, payload, length)) {
                free(payload);
                (void)fseek(h->fp, cur, SEEK_SET);
                return -1;
            }
        }

        if (read_exact(h->fp, chain_ext, sizeof(chain_ext))) {
            free(payload);
            (void)fseek(h->fp, cur, SEEK_SET);
            return -1;
        }

        uint64_t seq = le_to_u64(chain_ext);
        unsigned char* stored_prev = chain_ext + 8;
        if (memcmp(stored_prev, h->prev_hash, 32) != 0) {
            free(payload);
            (void)fseek(h->fp, cur, SEEK_SET);
            return -1;
        }

        compute_frame_hash(hdr_bytes, payload, length, h->prev_hash, frame_hash);
        memcpy(h->prev_hash, frame_hash, 32);
        h->next_seq_no = seq + 1;
    }

    free(payload);
    if (fseek(h->fp, 0, SEEK_END) != 0) return -1;
    return 0;
}

int frf_append_record(
    frf_handle_t* h, uint32_t type, uint64_t ts_unix_ns,
    const void* payload, uint32_t payload_len
    ) {
    if (!h || !h->fp || !h->is_writer) return -1;
    if (prepare_writer_chain(h) != 0) return -1;

    frf_record_header_t rh;
    rh.length = payload_len;
    rh.type   = type;
    rh.ts_unix_ns = ts_unix_ns;

    // Build a contiguous buffer for CRC over (type || ts || payload)
    size_t total = 4 + 8 + payload_len;
    unsigned char* crcbuf = malloc(total);
    if (!crcbuf) return -1;
    u32_to_le(rh.type, crcbuf + 0);
    u64_to_le(rh.ts_unix_ns, crcbuf + 4);
    if (payload_len && payload)
        memcpy(crcbuf + 12, payload, payload_len);
    rh.crc32 = frf_crc32(crcbuf, total);
    free(crcbuf);

    unsigned char hdr[20];
    u32_to_le(rh.length, hdr + 0);
    u32_to_le(rh.type, hdr + 4);
    u64_to_le(rh.ts_unix_ns, hdr + 8);
    u32_to_le(rh.crc32, hdr + 16);

    if (write_exact(h->fp, hdr, sizeof(hdr))) return -1;
    if (payload_len && payload)
        if (write_exact(h->fp, payload, payload_len)) return -1;

    unsigned char chain[FRF_CHAIN_BYTES];
    u64_to_le(h->next_seq_no, chain);
    memcpy(chain + 8, h->prev_hash, 32);
    if (write_exact(h->fp, chain, sizeof(chain))) return -1;

    unsigned char frame_hash[32];
    compute_frame_hash(hdr, payload_len ? (const unsigned char*)payload : NULL,
                       payload_len, h->prev_hash, frame_hash);
    memcpy(h->prev_hash, frame_hash, 32);
    h->prev_hash_valid = true;
    h->next_seq_no += 1;

    // Caller decides fsync cadence
    fflush(h->fp);
    return 0;
}

int frf_read_and_verify_header(frf_handle_t* h, frf_file_header_t* out) {
    if (!h || !h->fp) return -1;

    char magic[FRF_MAGIC_LEN];
    if (read_exact(h->fp, magic, FRF_MAGIC_LEN)) return -1;
    if (memcmp(magic, FRF_MAGIC, FRF_MAGIC_LEN) != 0) return -2;

    // Read the serialized 16-byte LE header
    unsigned char raw[16];
    if (read_exact(h->fp, raw, sizeof raw)) return -1;

    // Populate 'out' by decoding LE fields
    if (out) {
        out->flags = le_to_u32(raw + 0);
        out->created_unix_ns = le_to_u64(raw + 4);
    }

    // Compute header hash from the exact bytes we read
    compute_header_hash(h, raw);
    memcpy(h->prev_hash, h->header_hash, 32);
    h->prev_hash_valid = true;
    h->next_seq_no = 0;

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

    unsigned char chain_raw[FRF_CHAIN_BYTES];
    if (read_exact(h->fp, chain_raw, sizeof(chain_raw))) return -4;

    if (!h->prev_hash_valid) {
        if (!h->header_bytes_valid) return -7;
        memcpy(h->prev_hash, h->header_hash, 32);
        h->prev_hash_valid = true;
        h->next_seq_no = 0;
    }

    uint64_t seq = le_to_u64(chain_raw);
    const unsigned char* stored_prev = chain_raw + 8;
    if (seq != h->next_seq_no) return -7;
    if (memcmp(stored_prev, h->prev_hash, 32) != 0) return -7;

    unsigned char frame_hash[32];
    compute_frame_hash(raw, hdr->length ? (const unsigned char*)payload_buf : NULL,
                       hdr->length, h->prev_hash, frame_hash);
    memcpy(h->prev_hash, frame_hash, 32);
    h->prev_hash_valid = true;
    h->next_seq_no = seq + 1;

    if (out_len) *out_len = hdr->length;
    return 0;
}
