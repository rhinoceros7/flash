// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include "frf.h"
#include "flash/seal.h"

/* Exit codes */
enum {
    FLASH_VERIFY_OK = 0, /* sealed + FSIG verified */
    FLASH_VERIFY_UNSEALED = 1, /* FRF valid, but no valid FSIG trailer */
    FLASH_VERIFY_CORRUPT_FRF = 2, /* header or record-level corruption */
    FLASH_VERIFY_NOT_FLASH = 3, /* not a Flash file (bad magic/version) */
    FLASH_VERIFY_IO_ERROR = 4, /* fopen/fread/fseek etc. */
    FLASH_VERIFY_INTERNAL_ERROR = 5, /* unexpected internal error */
    FLASH_VERIFY_USAGE_ERROR = 64 /* bad CLI usage */
};

/* FSIG trailer size is fixed by the sealing spec (see seal.c). */
#define FLASH_FSIG_TRAILER_SIZE 200

typedef struct flash_verify_report_s {
    const char *path;
    bool is_flash;
    bool sealed;
    bool salvage; /* true if sealed & seal_mode == FLASH_SEAL_SALVAGE */
    uint64_t records; /* record count, when known */
    unsigned char chain_tip[32]; /* last known chain tip */
    uint8_t kid[8]; /* first 8 bytes of pubkey hash, when sealed */
    int exit_code;
    const char *status_str;
    char err_msg[256];
} flash_verify_report;

/* Small helper to zero-init report */
static void flash_verify_report_init(flash_verify_report *r, const char *path) {
    memset(r, 0, sizeof(*r));
    r->path = path;
    r->exit_code = FLASH_VERIFY_INTERNAL_ERROR;
    r->status_str = "internal_error";
}

/* Sealed path helpers */

/* After flash_seal_verify() has returned 0, parse basic metadata from FSIG. */
static int flash_verify_read_fsig_meta(flash_verify_report *rep) {
    FILE *f = fopen(rep->path, "rb");
    if (!f) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "open failed while reading FSIG: %s", strerror(errno));
        return FLASH_VERIFY_IO_ERROR;
    }

    /* Seek to trailer start */
    if (fseek(f, 0, SEEK_END) != 0) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "fseek(SEEK_END) failed while reading FSIG");
        fclose(f);
        return FLASH_VERIFY_IO_ERROR;
    }
    long end_pos = ftell(f);
    if (end_pos < 0) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "ftell() failed while reading FSIG");
        fclose(f);
        return FLASH_VERIFY_IO_ERROR;
    }
    if ((long)FLASH_FSIG_TRAILER_SIZE > end_pos) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "file shorter than FSIG trailer size");
        fclose(f);
        return FLASH_VERIFY_IO_ERROR;
    }

    if (fseek(f, end_pos - (long)FLASH_FSIG_TRAILER_SIZE, SEEK_SET) != 0) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "fseek() to FSIG trailer failed");
        fclose(f);
        return FLASH_VERIFY_IO_ERROR;
    }

    unsigned char tr[FLASH_FSIG_TRAILER_SIZE];
    size_t n = fread(tr, 1, sizeof(tr), f);
    if (n != sizeof(tr)) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "fread() FSIG trailer failed");
        fclose(f);
        return FLASH_VERIFY_IO_ERROR;
    }
    fclose(f);

    /* Layout must match seal.c:
       0..3: "FSIG"
       4: version
       5: hash_id
       6: reserved
       7: seal_mode
       8: salvage_reason
       9..11: reserved
       12..19: signed_length (u64 LE)
       20..27: records (u64 LE)
       28..59: digest (32)
       60..91: chain_tip (32)
       92..123: pubkey (32)
       124..187: signature (64)
       188..195: kid (8)
       196..199: trailer_crc32 (u32 LE)
    */

    /* We already know flash_seal_verify() succeeded, so we do not need to
       re-validate magic/version/hash_id. We only decode fields we care about. */

    uint8_t seal_mode = tr[7];
    rep->salvage = (seal_mode == FLASH_SEAL_SALVAGE);

    /* Records (LE u64 at offset 20) */
    const unsigned char *p = tr + 20;
    uint64_t rec = 0;
    for (int i = 7; i >= 0; --i) {
        rec = (rec << 8) | p[i];
    }
    rep->records = rec;

    /* Chain tip at offset 60 */
    memcpy(rep->chain_tip, tr + 60, 32);

    /* KID at offset 188 */
    memcpy(rep->kid, tr + 188, 8);

    rep->sealed = true;
    rep->is_flash = true;
    rep->exit_code = FLASH_VERIFY_OK;
    rep->status_str = rep->salvage
        ? "OK (sealed, SALVAGE)"
        : "OK (sealed, CLEAN)";

    return FLASH_VERIFY_OK;
}

/* FRF scan path (unsealed or no valid FSIG) */

static int flash_verify_scan_frf(flash_verify_report *rep) {
    frf_handle_t h;
    int rc = frf_open(rep->path, "rb", &h);
    if (rc != 0) {
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "frf_open() failed: %s", strerror(errno));
        rep->exit_code = FLASH_VERIFY_IO_ERROR;
        return FLASH_VERIFY_IO_ERROR;
    }

    frf_file_header_t fh;
    rc = frf_read_and_verify_header(&h, &fh);
    if (rc == -2) {
        /* Bad magic */
        frf_close(&h);
        rep->is_flash = false;
        rep->sealed = false;
        rep->exit_code = FLASH_VERIFY_NOT_FLASH;
        rep->status_str = "not_flash";
        return FLASH_VERIFY_NOT_FLASH;
    }
    if (rc != 0) {
        frf_close(&h);
        rep->is_flash = true;
        rep->sealed = false;
        rep->exit_code = FLASH_VERIFY_CORRUPT_FRF;
        rep->status_str = "corrupt_frf_header";
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "FRF header verification failed (rc=%d)", rc);
        return FLASH_VERIFY_CORRUPT_FRF;
    }

    rep->is_flash = true;
    rep->sealed = false;

    /* Iterate records to validate CRC + BLAKE3 chain */
    unsigned char buf[1 << 16];
    uint64_t rec_count = 0;

    for (;;) {
        frf_record_header_t rh;
        uint32_t out_len = 0;
        rc = frf_next_record(&h, &rh, buf, (uint32_t)sizeof(buf), &out_len);
        if (rc == 0) {
            /* Record OK */
            rec_count++;
            continue;
        }
        if (rc == 1) {
            /* Clean EOF */
            break;
        }
        /* Any negative code is corruption/truncation/chain failure */
        frf_close(&h);
        rep->records = rec_count;
        rep->exit_code = FLASH_VERIFY_CORRUPT_FRF;
        rep->status_str = "corrupt_frf_records";
        snprintf(rep->err_msg, sizeof(rep->err_msg),
                 "FRF record scan failed (rc=%d)", rc);
        return FLASH_VERIFY_CORRUPT_FRF;
    }

    /* Expose chain tip */
    frf_get_chain_tip(&h, rep->chain_tip);
    frf_close(&h);

    rep->records = rec_count;
    rep->exit_code = FLASH_VERIFY_UNSEALED;
    rep->status_str = "UNSEALED (FRF OK, no valid FSIG)";

    return FLASH_VERIFY_UNSEALED;
}

/* Output helpers */

static void flash_verify_print_human(const flash_verify_report *rep, int verbose) {
    switch (rep->exit_code) {
    case FLASH_VERIFY_OK:
        printf("OK %s\n", rep->path);
        printf("sealed: yes\n");
        printf("salvage: %s\n", rep->salvage ? "true" : "false");
        printf("records: %llu\n", (unsigned long long)rep->records);
        if (verbose) {
            printf("kid: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                   rep->kid[0], rep->kid[1], rep->kid[2], rep->kid[3],
                   rep->kid[4], rep->kid[5], rep->kid[6], rep->kid[7]);
        }
        break;
    case FLASH_VERIFY_UNSEALED:
        printf("UNSEALED %s\n", rep->path);
        printf("sealed: no (no valid FSIG trailer)\n");
        printf("records: %llu\n", (unsigned long long)rep->records);
        if (verbose) {
            printf("note: CRC and BLAKE3 chain verified over all records\n");
        }
        break;
    case FLASH_VERIFY_NOT_FLASH:
        printf("ERROR %s\n", rep->path);
        printf("error: not a Flash file (bad magic/version)\n");
        break;
    case FLASH_VERIFY_CORRUPT_FRF:
        printf("CORRUPT %s\n", rep->path);
        printf("error: %s\n", rep->err_msg[0] ? rep->err_msg : "FRF corruption");
        break;
    case FLASH_VERIFY_IO_ERROR:
        printf("ERROR %s\n", rep->path);
        printf("error: I/O error: %s\n", rep->err_msg[0] ? rep->err_msg : "unknown");
        break;
    default:
        printf("ERROR %s\n", rep->path);
        printf("error: internal error\n");
        break;
    }
}

static void flash_verify_print_json(const flash_verify_report *rep) {
    const char *status = rep->status_str ? rep->status_str : "unknown";
    (void)status; /* reserved if we want to emit it later */

    printf("{\"file\":\"%s\",\"exit_code\":%d,"
           "\"is_flash\":%s,\"sealed\":%s,\"salvage\":%s,"
           "\"records\":%llu}\n",
           rep->path,
           rep->exit_code,
           rep->is_flash ? "true" : "false",
           rep->sealed ? "true" : "false",
           rep->salvage ? "true" : "false",
           (unsigned long long)rep->records);
}

/* Public CLI entrypoint */

int cmd_verify(int argc, char **argv) {
    int quiet = 0;
    int verbose = 0;
    int as_json = 0;
    const char *path = NULL;

    /* argv[0] is "verify"; parse flags starting at argv[1]. */
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (arg[0] == '-') {
            if (!strcmp(arg, "-q") || !strcmp(arg, "--quiet")) {
                quiet = 1;
            } else if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
                verbose = 1;
            } else if (!strcmp(arg, "--json")) {
                as_json = 1;
            } else {
                fprintf(stderr, "flash verify: unknown option: %s\n", arg);
                fprintf(stderr, "usage: flash verify [--json] [-q|-v] FILE.flsh\n");
                return FLASH_VERIFY_USAGE_ERROR;
            }
        } else {
            if (path) {
                fprintf(stderr, "flash verify: multiple files not supported yet\n");
                fprintf(stderr, "usage: flash verify [--json] [-q|-v] FILE.flsh\n");
                return FLASH_VERIFY_USAGE_ERROR;
            }
            path = arg;
        }
    }

    if (!path) {
        fprintf(stderr, "usage: flash verify [--json] [-q|-v] FILE.flsh\n");
        return FLASH_VERIFY_USAGE_ERROR;
    }

    flash_verify_report rep;
    flash_verify_report_init(&rep, path);

    int seal_rc = flash_seal_verify(path);
    if (seal_rc == 0) {
        int meta_rc = flash_verify_read_fsig_meta(&rep);
        if (meta_rc != FLASH_VERIFY_OK) {
            rep.exit_code = meta_rc;
        }
    } else if (seal_rc == -2) {
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "flash_seal_verify() failed to open: %s", strerror(errno));
        rep.exit_code = FLASH_VERIFY_IO_ERROR;
    } else {
        (void)flash_verify_scan_frf(&rep);
    }

    if (!quiet) {
        if (as_json) {
            flash_verify_print_json(&rep);
        } else {
            flash_verify_print_human(&rep, verbose);
        }
    }

    return rep.exit_code;
}
