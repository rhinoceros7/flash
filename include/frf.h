#ifndef FRF_H
#define FRF_H

// do NOT change FRF_RECORD_HEADER_BYTES
#define FRF_RECORD_HEADER_BYTES 20

#define FRF_FILE_HEADER_BYTES (FRF_MAGIC_LEN + 16)
#define FRF_CHAIN_BYTES 40
#define FRF_FRAME_OVERHEAD (FRF_RECORD_HEADER_BYTES + FRF_CHAIN_BYTES)

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

#define FRF_MAGIC "FLSHv001"
#define FRF_MAGIC_LEN  8

// Record types are user-defined; core does not enforce semantics.
typedef struct {
    uint32_t flags; // reserved for future
    uint64_t created_unix_ns; // file creation time
} frf_file_header_t;

typedef struct {
    uint32_t length; // payload length in bytes
    uint32_t type; // user record type
    uint64_t ts_unix_ns; // event time
    uint32_t crc32; // CRC32 over (type || ts_unix_ns || payload)
} frf_record_header_t;

// On-disk layout for each record header is fixed 20 bytes, little-endian:
// length[4] | type[4] | ts_unix_ns[8] | crc32[4]
// Do NOT fwrite/fread the struct directly; pack/unpack explicitly in frf.c.


typedef struct {
    FILE* fp;
    bool is_writer;
    bool header_bytes_valid;
    bool prev_hash_valid;
    unsigned char header_bytes[16];
    unsigned char header_hash[32];
    unsigned char prev_hash[32];
    uint64_t next_seq_no;
} frf_handle_t;

/* Open/create .flsh
   mode: "wb+" new, "ab+" append, "rb" read */
int  frf_open(const char* path, const char* mode, frf_handle_t* out);
void frf_close(frf_handle_t* h);

/* Write file header if file is empty (idempotent). */
int  frf_write_header_if_new(frf_handle_t* h, uint64_t created_unix_ns);

/* Append a record. Returns 0 on success. */
int  frf_append_record(frf_handle_t* h,
                       uint32_t type,
                       uint64_t ts_unix_ns,
                       const void* payload,
                       uint32_t payload_len);

/* Read & verify header. Returns 0 if valid, -2 if bad magic. */
int  frf_read_and_verify_header(frf_handle_t* h, frf_file_header_t* out);

/* Iterate records. Returns:
   0 = got record, 1 = clean EOF, negative = error/truncation. */
int  frf_next_record(
    frf_handle_t* h, frf_record_header_t* hdr, void* payload_buf,
    uint32_t buf_cap, uint32_t* out_len);

/* CRC32 utility (IEEE/poly 0xEDB88320). */
uint32_t frf_crc32(const void* data, size_t n);

// Expose the current chain tip (last frame hash)
// If no frames yet, returns the header hash if present, else zeros.
void frf_get_chain_tip(const frf_handle_t* h, unsigned char out32[32]);

#endif
