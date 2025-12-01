#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>

#include "frf.h"
#include "flash/seal.h"

#ifndef EX_USAGE
#define EX_USAGE 64
#endif

// Must match FSIG_TRAILER_SIZE in seal.c
enum { FSIG_TRAILER_SIZE = 200 };


// Forward decl from index.c so we can call it for --index.
int cmd_index(int argc, char **argv); /* Implemented in index.c */

// Hard cap on payload size we’re willing to merge per record (16 MiB).
// This matches size used elsewhere.
#define MERGE_MAX_PAYLOAD (16u * 1024u * 1024u)

/* Case-insensitive equality */
static int strings_equal_ci(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca - 'A' + 'Z' - 25); // 'a' = 'z' - 25
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb - 'A' + 'Z' - 25);
        if (ca != cb) return 0;
        ++a; ++b;
    }
    return *a == '\0' && *b == '\0';
}

/* Tiny LE helpers that mirror frf.c */
static uint32_t rd_u32le(const unsigned char* p) {
    return (uint32_t)p[0] |
           (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static uint64_t rd_u64le(const unsigned char* p) {
    uint32_t lo = rd_u32le(p);
    uint32_t hi = rd_u32le(p + 4);
    return (uint64_t)hi << 32 | (uint64_t)lo;
}

/* “Now” in ns since Unix epoch – coarse but good enough for created_unix_ns. */
static uint64_t now_unix_ns(void) {
    time_t secs = time(NULL);
    if (secs < 0) return 0;
    return (uint64_t)secs * 1000000000ULL;
}

typedef struct {
    const char* path;
    uint64_t created_ns;
    uint64_t first_ts;
    int has_ts;
    uint64_t filesize;
    int original_index; // for stable-ish sorting
} merge_input;

typedef struct {
    int verify_inputs;
    int concat_only;
    int build_index;
} merge_opts;

/* Get filesize via stdio, cross-platform-ish. */
static int get_filesize(FILE* f, uint64_t* out_size) {
#if defined(_WIN32)
    __int64 cur = _ftelli64(f);
    if (cur < 0) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) return -1;
    __int64 end = _ftelli64(f);
    if (end < 0) return -1;
    if (_fseeki64(f, cur, SEEK_SET) != 0) return -1;
    *out_size = (uint64_t)end;
    return 0;
#else
    off_t cur = ftello(f);
    if (cur < 0) return -1;
    if (fseeko(f, 0, SEEK_END) != 0) return -1;
    off_t end = ftello(f);
    if (end < 0) return -1;
    if (fseeko(f, cur, SEEK_SET) != 0) return -1;
    *out_size = (uint64_t)end;
    return 0;
#endif
}

/* Probe a single input:
 * - Optionally verify FSIG
 * - Check FRF magic + header
 * - Find first timestamp (if any)
 * - Fill merge_input metadata
 */
static int probe_input(const char* path,
                       const merge_opts* opts,
                       merge_input* out_meta) {
    if (opts->verify_inputs) {
        int vrc = flash_seal_verify(path);
        if (vrc != 0) {
            fprintf(stderr,
                    "flash merge: verify failed for '%s' (code=%d)\n",
                    path, vrc);
            return 2;
        }
    }

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr,
                "flash merge: failed to open '%s': %s\n",
                path, strerror(errno));
        return 2;
    }

    uint64_t filesize = 0;
    if (get_filesize(f, &filesize) != 0) {
        fprintf(stderr,
                "flash merge: could not stat '%s'\n", path);
        fclose(f);
        return 2;
    }

    if (filesize < FRF_FILE_HEADER_BYTES) {
        fprintf(stderr,
                "flash merge: '%s' too small to be a valid .flsh file\n",
                path);
        fclose(f);
        return 2;
    }

    // Frames live in [0 .. frames_end). For sealed files, the last 200 bytes
    // are the FSIG trailer and must NOT be treated as FRF frames.
    uint64_t frames_end = filesize;
    if (filesize >= FSIG_TRAILER_SIZE) {
        frames_end = filesize - FSIG_TRAILER_SIZE;
    }

    unsigned char magic[FRF_MAGIC_LEN];
    if (fread(magic, 1, FRF_MAGIC_LEN, f) != FRF_MAGIC_LEN) {
        fprintf(stderr,
                "flash merge: failed to read magic from '%s'\n", path);
        fclose(f);
        return 2;
    }
    if (memcmp(magic, FRF_MAGIC, FRF_MAGIC_LEN) != 0) {
        fprintf(stderr,
                "flash merge: bad magic in '%s'\n", path);
        fclose(f);
        return 2;
    }

    unsigned char header_raw[16];
    if (fread(header_raw, 1, sizeof(header_raw), f) != sizeof(header_raw)) {
        fprintf(stderr,
                "flash merge: truncated FRF header in '%s'\n", path);
        fclose(f);
        return 2;
    }

    uint32_t flags = rd_u32le(header_raw + 0);
    (void)flags;
    uint64_t created_ns = rd_u64le(header_raw + 4);

    uint64_t pos = FRF_FILE_HEADER_BYTES;
    uint64_t first_ts = 0;
    int have_ts = 0;

    for (;;) {
        // Use frames_end here instead of filesize
        if (pos + FRF_RECORD_HEADER_BYTES > frames_end) {
            break;
        }

        unsigned char hdr_raw[FRF_RECORD_HEADER_BYTES];
        size_t n = fread(hdr_raw, 1, sizeof(hdr_raw), f);
        if (n == 0) {
            break;
        }
        if (n != sizeof(hdr_raw)) {
            break;
        }

        uint32_t length = rd_u32le(hdr_raw + 0);
        uint64_t ts = rd_u64le(hdr_raw + 8);

        if (length > MERGE_MAX_PAYLOAD) {
            fprintf(stderr,
                    "flash merge: record length %" PRIu32 " in '%s' exceeds max (%u)\n",
                    length, path, MERGE_MAX_PAYLOAD);
            fclose(f);
            return 2;
        }

        uint64_t frame_bytes = (uint64_t)FRF_RECORD_HEADER_BYTES +
                               (uint64_t)length +
                               (uint64_t)FRF_CHAIN_BYTES;

        if (pos + frame_bytes > frames_end) {
            break;
        }

        if (!have_ts) {
            first_ts = ts;
            have_ts  = 1;
        }

        // Skip payload + chain
#if defined(_WIN32)
        if (_fseeki64(f, (int64_t)length + (int64_t)FRF_CHAIN_BYTES, SEEK_CUR) != 0) {
            fclose(f);
            return 2;
        }
#else
        if (fseeko(f, (off_t)length + (off_t)FRF_CHAIN_BYTES, SEEK_CUR) != 0) {
            fclose(f);
            return 2;
        }
#endif
        pos += frame_bytes;
    }

    fclose(f);

    out_meta->path = path;
    out_meta->created_ns = created_ns;
    out_meta->first_ts = first_ts;
    out_meta->has_ts = have_ts;
    out_meta->filesize = filesize;
    return 0;
}

/* Copy all FRF frames from one input into the output FRF writer.
 * Re-encodes headers, CRC, and BLAKE3 chain; ignores the FSIG trailer.
 */
static int merge_copy_one_input(const merge_input* in,
                                frf_handle_t* out,
                                uint64_t* total_records) {
    const char* path = in->path;
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr,
                "flash merge: failed to open input '%s': %s\n",
                path, strerror(errno));
        return 2;
    }

    uint64_t filesize = in->filesize;
    if (filesize < FRF_FILE_HEADER_BYTES) {
        fprintf(stderr,
                "flash merge: '%s' too small to be a valid .flsh file\n",
                path);
        fclose(f);
        return 2;
    }

    // Same logic: frames live in [0 .. frames_end)
    uint64_t frames_end = filesize;
    if (filesize >= FSIG_TRAILER_SIZE) {
        frames_end = filesize - FSIG_TRAILER_SIZE;
    }

    // Skip magic + FRF header
    unsigned char skip[FRF_FILE_HEADER_BYTES];
    if (fread(skip, 1, FRF_FILE_HEADER_BYTES, f) != FRF_FILE_HEADER_BYTES) {
        fprintf(stderr,
                "flash merge: failed to re-read header for '%s'\n", path);
        fclose(f);
        return 2;
    }

    uint64_t pos = FRF_FILE_HEADER_BYTES;

    unsigned char* payload = NULL;
    uint32_t payload_cap = 0;

    for (;;) {
        if (pos + FRF_RECORD_HEADER_BYTES > frames_end) {
            break;
        }

        unsigned char hdr_raw[FRF_RECORD_HEADER_BYTES];
        size_t n = fread(hdr_raw, 1, sizeof(hdr_raw), f);
        if (n == 0) {
            break;
        }
        if (n != sizeof(hdr_raw)) {
            break;
        }

        uint32_t length = rd_u32le(hdr_raw + 0);
        uint32_t type = rd_u32le(hdr_raw + 4);
        uint64_t ts = rd_u64le(hdr_raw + 8);
        uint32_t crc = rd_u32le(hdr_raw + 16);
        (void)crc;

        if (length > MERGE_MAX_PAYLOAD) {
            fprintf(stderr,
                    "flash merge: record length %" PRIu32 " in '%s' exceeds max (%u)\n",
                    length, path, MERGE_MAX_PAYLOAD);
            free(payload);
            fclose(f);
            return 2;
        }

        uint64_t frame_bytes = (uint64_t)FRF_RECORD_HEADER_BYTES +
                               (uint64_t)length +
                               (uint64_t)FRF_CHAIN_BYTES;

        if (pos + frame_bytes > frames_end) {
            break;
        }

        // Read payload
        if (length > 0) {
            if (length > payload_cap) {
                unsigned char* new_buf = realloc(payload, length);
                if (!new_buf) {
                    fprintf(stderr,
                            "flash merge: OOM reading '%s'\n", path);
                    free(payload);
                    fclose(f);
                    return 2;
                }
                payload = new_buf;
                payload_cap = length;
            }
            if (fread(payload, 1, length, f) != length) {
                fprintf(stderr,
                        "flash merge: truncated payload in '%s'\n", path);
                free(payload);
                fclose(f);
                return 2;
            }
        }

        // Skip original chain extension bytes
        unsigned char chain_ext[FRF_CHAIN_BYTES];
        if (fread(chain_ext, 1, sizeof(chain_ext), f) != sizeof(chain_ext)) {
            fprintf(stderr,
                    "flash merge: truncated chain extension in '%s'\n", path);
            free(payload);
            fclose(f);
            return 2;
        }

        // Append record into output with fresh CRC + BLAKE3 chain.
        int arc = frf_append_record(out, type, ts,
                                    length ? payload : NULL, length);
        if (arc != 0) {
            fprintf(stderr,
                    "flash merge: failed to append record from '%s'\n", path);
            free(payload);
            fclose(f);
            return 2;
        }

        (*total_records)++;
        pos += frame_bytes;
    }

    free(payload);
    fclose(f);
    return 0;
}

/* Comparator for qsort when not using --concat-only.
 * Sort by first_ts (if present), then by created_ns, then original_index.
 */
static int merge_input_cmp(const void* a, const void* b) {
    const merge_input* ia = a;
    const merge_input* ib = b;

    if (ia->has_ts && ib->has_ts) {
        if (ia->first_ts < ib->first_ts) return -1;
        if (ia->first_ts > ib->first_ts) return 1;
        // tie: fall through
    } else if (ia->has_ts && !ib->has_ts) {
        return -1;
    } else if (!ia->has_ts && ib->has_ts) {
        return 1;
    } else {
        // neither has ts: fall back to created_ns
        if (ia->created_ns < ib->created_ns) return -1;
        if (ia->created_ns > ib->created_ns) return 1;
    }

    // Final tie-breaker: original index
    if (ia->original_index < ib->original_index) return -1;
    if (ia->original_index > ib->original_index) return 1;
    return 0;
}

static void print_merge_usage(void) {
    fprintf(stderr,
            "usage: flash merge [--verify] [--concat-only] [--index] "
            "OUT.flsh IN1.flsh [IN2.flsh ...]\n");
}

int cmd_merge(int argc, char** argv) {
    if (argc < 3) {
        print_merge_usage();
        return EX_USAGE;
    }

    merge_opts opts;
    memset(&opts, 0, sizeof(opts));

    int idx = 1; // argv[0] == "merge"
    while (idx < argc && argv[idx][0] == '-') {
        const char* tok = argv[idx++];
        if (strings_equal_ci(tok, "--verify")) {
            opts.verify_inputs = 1;
        } else if (strings_equal_ci(tok, "--concat-only")) {
            opts.concat_only = 1;
        } else if (strings_equal_ci(tok, "--index")) {
            opts.build_index = 1;
        } else {
            fprintf(stderr, "flash merge: unknown option '%s'\n", tok);
            print_merge_usage();
            return EX_USAGE;
        }
    }

    if (idx >= argc) {
        fprintf(stderr, "flash merge: missing OUT.flsh\n");
        print_merge_usage();
        return EX_USAGE;
    }

    const char* out_path = argv[idx++];
    if (idx >= argc) {
        fprintf(stderr, "flash merge: need at least one input file\n");
        print_merge_usage();
        return EX_USAGE;
    }

    int input_count = argc - idx;
    merge_input* inputs = calloc((size_t)input_count,
                                 sizeof(merge_input));
    if (!inputs) {
        fprintf(stderr, "flash merge: OOM allocating input metadata\n");
        return 2;
    }

    // Probe all inputs
    int meta_err = 0;
    for (int i = 0; i < input_count; ++i) {
        inputs[i].original_index = i;
        int rc = probe_input(argv[idx + i], &opts, &inputs[i]);
        if (rc != 0) {
            meta_err = rc;
            break;
        }
    }

    if (meta_err != 0) {
        free(inputs);
        return meta_err;
    }

    // Sort by time if not concat-only
    if (!opts.concat_only && input_count > 1) {
        qsort(inputs, (size_t)input_count, sizeof(merge_input),
              merge_input_cmp);
    }

    // Create output + FRF header.
    frf_handle_t out;
    if (frf_open(out_path, "wb+", &out) != 0) {
        fprintf(stderr,
                "flash merge: failed to open output '%s'\n", out_path);
        free(inputs);
        return 2;
    }

    uint64_t created_ns = now_unix_ns();
    if (frf_write_header_if_new(&out, created_ns) != 0) {
        fprintf(stderr,
                "flash merge: failed to write FRF header for '%s'\n",
                out_path);
        frf_close(&out);
        free(inputs);
        return 2;
    }

    // Copy frames
    uint64_t total_records = 0;
    for (int i = 0; i < input_count; ++i) {
        int rc = merge_copy_one_input(&inputs[i], &out, &total_records);
        if (rc != 0) {
            fprintf(stderr,
                    "flash merge: aborting due to error on '%s'\n",
                    inputs[i].path);
            frf_close(&out);
            free(inputs);
            return rc;
        }
    }

    // Capture chain tip and close FRF writer
    uint8_t chain_tip[32];
    frf_get_chain_tip(&out, chain_tip);
    frf_close(&out);

    // Seal merged file with CLEAN seal
    flash_seal_result seal_res;
    int s_rc = flash_seal_append_fsig(out_path,
                                      FLASH_SEAL_CLEAN,
                                      FLASH_SALVAGE_OK,
                                      chain_tip,
                                      total_records,
                                      &seal_res);
    if (s_rc != 0) {
        fprintf(stderr,
                "flash merge: sealing '%s' failed (code=%d)\n",
                out_path, s_rc);
        free(inputs);
        return 2;
    }

    // Optional index build
    if (opts.build_index) {
        char* idx_argv[3];
        idx_argv[0] = (char*)"index";
        idx_argv[1] = (char*)out_path;
        int rc = cmd_index(2, idx_argv);
        if (rc != 0) {
            fprintf(stderr,
                    "flash merge: index build failed for '%s' (code=%d)\n",
                    out_path, rc);
            // Not fatal for the merged file itself, so we don’t override rc.
        }
    }

    printf("merge: wrote '%s' from %d input file(s) "
           "(records=%" PRIu64 ", signed_length=%" PRIu64 ")\n",
           out_path,
           input_count,
           seal_res.records,
           seal_res.signed_length);

    free(inputs);
    return 0;
}
