#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <io.h>
#include <stdint.h>
#include <stdbool.h>

#include "frf.h"
#include "flash/seal.h"

/* Exit codes */
enum {
    FLASH_REPAIR_OK = 0,
    FLASH_REPAIR_UNRECOVERABLE  = 2, /* FRF but no salvageable frames */
    FLASH_REPAIR_NOT_FLASH = 3, /* not an FRF/Flash file */
    FLASH_REPAIR_IO_ERROR = 4, /* fopen/read/write/truncate issues */
    FLASH_REPAIR_INTERNAL_ERROR = 5, /* unexpected internal error */
    FLASH_REPAIR_USAGE_ERROR = 64 /* bad CLI usage */
};

typedef struct {
    const char *path;
    int exit_code;

    int dry_run;
    int quiet;
    int verbose;
    int as_json;

    int sealed_before;
    int sealed_after;
    int modified; /* file actually changed on disk */
    int salvage_applied; /* we planned a SALVAGE seal (even in dry-run) */

    flash_salvage_reason salvage_reason;

    uint64_t records_kept;

    char err_msg[256];
} flash_repair_report;

/* Cross-platform truncate helper */
static int truncate_file(const char *path, uint64_t new_size,
                         char *err_msg, size_t err_cap) {
    if (!path) {
        snprintf(err_msg, err_cap, "no path provided");
        return -1;
    }

    FILE *f = fopen(path, "rb+");
    if (!f) {
        snprintf(err_msg, err_cap, "fopen(%s) failed: %s", path, strerror(errno));
        return -1;
    }

#if defined(_WIN32)
    int fd = _fileno(f);
    if (fd < 0) {
        snprintf(err_msg, err_cap, "_fileno failed: %s", strerror(errno));
        fclose(f);
        return -1;
    }
    if (_chsize_s(fd, (int64_t)new_size) != 0) {
        snprintf(err_msg, err_cap, "_chsize_s failed: %s", strerror(errno));
        fclose(f);
        return -1;
    }
    fflush(f);
    _commit(fd);
#else
    int fd = fileno(f);
    if (fd < 0) {
        snprintf(err_msg, err_cap, "fileno failed: %s", strerror(errno));
        fclose(f);
        return -1;
    }
    if (ftruncate(fd, (off_t)new_size) != 0) {
        snprintf(err_msg, err_cap, "ftruncate failed: %s", strerror(errno));
        fclose(f);
        return -1;
    }
    fsync(fd);
#endif

    fclose(f);
    return 0;
}

static const char *salvage_reason_name(flash_salvage_reason r) {
    switch (r) {
    case FLASH_SALVAGE_OK: return "ok";
    case FLASH_SALVAGE_PARTIAL_TRAILER: return "partial_trailer";
    case FLASH_SALVAGE_CHAIN_FAIL: return "chain_fail";
    case FLASH_SALVAGE_CRC_FAIL: return "crc_fail";
    case FLASH_SALVAGE_MISSING_RUN_CLOSE: return "missing_run_close";
    case FLASH_SALVAGE_NO_VALID_FRAMES: return "no_valid_frames";
    default: return "unknown";
    }
}

static void flash_repair_report_init(flash_repair_report *rep,
                                     const char *path) {
    memset(rep, 0, sizeof(*rep));
    rep->path = path;
    rep->exit_code = FLASH_REPAIR_INTERNAL_ERROR;
    rep->salvage_reason = FLASH_SALVAGE_OK;
}

static void flash_repair_print_human(const flash_repair_report *rep) {
    /* Errors first */
    switch (rep->exit_code) {
    case FLASH_REPAIR_USAGE_ERROR:
        /* usage already printed by caller */
        return;
    case FLASH_REPAIR_IO_ERROR:
        fprintf(stderr, "repair: I/O error on %s: %s\n",
                rep->path,
                rep->err_msg[0] ? rep->err_msg : "unknown");
        return;
    case FLASH_REPAIR_NOT_FLASH:
        fprintf(stderr, "repair: not a Flash/FRF file: %s\n", rep->path);
        if (rep->err_msg[0]) {
            fprintf(stderr, "repair: detail: %s\n", rep->err_msg);
        }
        return;
    case FLASH_REPAIR_UNRECOVERABLE:
        fprintf(stderr, "repair: unrecoverable; no valid frames to salvage in %s\n",
                rep->path);
        if (rep->err_msg[0]) {
            fprintf(stderr, "repair: detail: %s\n", rep->err_msg);
        }
        return;
    case FLASH_REPAIR_INTERNAL_ERROR:
        fprintf(stderr, "repair: internal error on %s", rep->path);
        if (rep->err_msg[0]) {
            fprintf(stderr, ": %s", rep->err_msg);
        }
        fputc('\n', stderr);
        return;
    default:
        break;
    }

    /* Success / no-op path */
    if (rep->sealed_before && !rep->salvage_applied) {
        if (!rep->quiet) {
            printf("repair: already sealed, nothing to do: %s\n", rep->path);
        }
        return;
    }

    const char *reason_str = salvage_reason_name(rep->salvage_reason);

    if (rep->dry_run) {
        if (!rep->quiet) {
            if (rep->modified) {
                /* For dry-run, modified should always be 0, but keep text defensive. */
                printf("repair: DRY-RUN: would truncate and seal (SALVAGE) %s; "
                       "keep %llu records; reason=%s\n",
                       rep->path,
                       (unsigned long long)rep->records_kept,
                       reason_str);
            } else {
                printf("repair: DRY-RUN: would seal (SALVAGE) %s; "
                       "keep %llu records; reason=%s\n",
                       rep->path,
                       (unsigned long long)rep->records_kept,
                       reason_str);
            }
        }
    } else {
        if (!rep->quiet) {
            if (rep->modified) {
                printf("repair: truncated and sealed (SALVAGE) %s; "
                       "kept %llu records; reason=%s\n",
                       rep->path,
                       (unsigned long long)rep->records_kept,
                       reason_str);
            } else {
                printf("repair: sealed (SALVAGE) %s; "
                       "kept %llu records; reason=%s\n",
                       rep->path,
                       (unsigned long long)rep->records_kept,
                       reason_str);
            }
        }
    }

    if (rep->verbose && !rep->quiet) {
        printf("sealed_before=%s sealed_after=%s dry_run=%s\n",
               rep->sealed_before ? "true" : "false",
               rep->sealed_after ? "true" : "false",
               rep->dry_run ? "true" : "false");
    }
}

static void flash_repair_print_json(const flash_repair_report *rep) {
    const char *reason_str = salvage_reason_name(rep->salvage_reason);

    printf("{"
           "\"file\":\"%s\","
           "\"exit_code\":%d,"
           "\"sealed_before\":%s,"
           "\"sealed_after\":%s,"
           "\"modified\":%s,"
           "\"dry_run\":%s,"
           "\"salvage_applied\":%s,"
           "\"salvage_reason\":%d,"
           "\"salvage_reason_str\":\"%s\","
           "\"records_kept\":%llu",
           rep->path,
           rep->exit_code,
           rep->sealed_before ? "true" : "false",
           rep->sealed_after ? "true" : "false",
           rep->modified ? "true" : "false",
           rep->dry_run ? "true" : "false",
           rep->salvage_applied ? "true" : "false",
           (int)rep->salvage_reason,
           reason_str,
           (unsigned long long)rep->records_kept);

    if (rep->err_msg[0]) {
        printf(",\"error\":\"%s\"", rep->err_msg);
    }

    printf("}\n");
}

int cmd_repair(int argc, char **argv) {
    int quiet = 0;
    int verbose = 0;
    int as_json = 0;
    int dry_run = 0;
    const char *path = NULL;

    /* argv[0] is "repair"; parse flags starting at argv[1]. */
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (arg[0] == '-') {
            if (!strcmp(arg, "-q") || !strcmp(arg, "--quiet")) {
                quiet = 1;
            } else if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
                verbose = 1;
            } else if (!strcmp(arg, "--json")) {
                as_json = 1;
            } else if (!strcmp(arg, "--dry-run")) {
                dry_run = 1;
            } else {
                fprintf(stderr, "flash repair: unknown option: %s\n", arg);
                fprintf(stderr,
                        "usage: flash repair [--json] [--dry-run] [-q|-v] FILE.flsh\n");
                return FLASH_REPAIR_USAGE_ERROR;
            }
        } else {
            if (path) {
                fprintf(stderr,
                        "flash repair: multiple files not supported yet\n");
                fprintf(stderr,
                        "usage: flash repair [--json] [--dry-run] [-q|-v] FILE.flsh\n");
                return FLASH_REPAIR_USAGE_ERROR;
            }
            path = arg;
        }
    }

    if (!path) {
        fprintf(stderr,
                "usage: flash repair [--json] [--dry-run] [-q|-v] FILE.flsh\n");
        return FLASH_REPAIR_USAGE_ERROR;
    }

    flash_repair_report rep;
    flash_repair_report_init(&rep, path);
    rep.dry_run = dry_run;
    rep.quiet = quiet;
    rep.verbose = verbose;
    rep.as_json = as_json;

    /* If already sealed (CLEAN or SALVAGE), do nothing. */
    /* Sealed means immutable, will never be modified by Flash again. */
    int seal_rc = flash_seal_verify(path);
    if (seal_rc == 0) {
        rep.sealed_before = 1;
        rep.sealed_after = 1;
        rep.modified = 0;
        rep.salvage_applied = 0;
        rep.exit_code = FLASH_REPAIR_OK;

        if (!rep.quiet) {
            if (rep.as_json) {
                flash_repair_print_json(&rep);
            } else {
                flash_repair_print_human(&rep);
            }
        }
        return rep.exit_code;
    }
    if (seal_rc == -2) {
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "flash_seal_verify() failed to open: %s", strerror(errno));
        rep.exit_code = FLASH_REPAIR_IO_ERROR;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    /* Any other seal_rc: no valid FSIG, truncated FSIG, or mismatch.
       Drop down to FRF-level inspection and salvage. */

    frf_handle_t h;
    int rc = frf_open(path, "rb", &h);
    if (rc != 0) {
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "frf_open(%s) failed: %s", path, strerror(errno));
        rep.exit_code = FLASH_REPAIR_IO_ERROR;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    frf_file_header_t fh;
    rc = frf_read_and_verify_header(&h, &fh);
    if (rc != 0) {
        /* Header is bad or not an FRF/Flash file. We do not try to repair that. */
        frf_close(&h);
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "FRF header verification failed (rc=%d)", rc);
        rep.exit_code = FLASH_REPAIR_NOT_FLASH;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    /* Scan records and track last good frame offset. */
    unsigned char buf[1 << 16];
    uint64_t record_count = 0;
    uint64_t last_good_offset = FRF_FILE_HEADER_BYTES;
    int scan_rc = 0; /* 1 = clean EOF, <0 = corruption */

    for (;;) {
        frf_record_header_t rh;
        uint32_t out_len = 0;
        rc = frf_next_record(&h, &rh, buf, sizeof(buf), &out_len);
        if (rc == 0) {
            record_count++;
            last_good_offset += (uint64_t)FRF_FRAME_OVERHEAD +
                                (uint64_t)rh.length;
            continue;
        }
        if (rc == 1) {
            /* Clean EOF from FRF perspective. */
            scan_rc = 1;
            break;
        }
        /* Negative rc: truncated header/payload, CRC fail, chain fail, etc. */
        scan_rc = rc;
        break;
    }

    uint8_t chain_tip[32];
    frf_get_chain_tip(&h, chain_tip);
    frf_close(&h);

    rep.records_kept = record_count;

    if (record_count == 0) {
        rep.salvage_reason = FLASH_SALVAGE_NO_VALID_FRAMES;
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "no valid frames before corruption");
        rep.exit_code = FLASH_REPAIR_UNRECOVERABLE;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    /* Map FRF scan result to salvage reason. */
    flash_salvage_reason reason = FLASH_SALVAGE_OK;
    if (scan_rc == 1) {
        /* FRF OK, but file is effectively unsealed at Flash level. */
        reason = FLASH_SALVAGE_MISSING_RUN_CLOSE;
    } else if (scan_rc < 0) {
        switch (scan_rc) {
        case -2: /* truncated header */
        case -4: /* truncated payload or chain */
            reason = FLASH_SALVAGE_PARTIAL_TRAILER;
            break;
        case -6: /* CRC mismatch */
            reason = FLASH_SALVAGE_CRC_FAIL;
            break;
        case -7: /* chain mismatch */
            reason = FLASH_SALVAGE_CHAIN_FAIL;
            break;
        default:
            reason = FLASH_SALVAGE_CHAIN_FAIL;
            break;
        }
    }
    rep.salvage_reason = reason;
    rep.salvage_applied = 1;

    /* Decide and apply repair strategy. */

    if (rep.dry_run) {
        /* In dry-run we just report what would be done. */
        rep.sealed_before = 0;
        rep.sealed_after = 0;
        rep.modified = 0;
        rep.exit_code = FLASH_REPAIR_OK;

        if (!rep.quiet) {
            if (rep.as_json) {
                flash_repair_print_json(&rep);
            } else {
                flash_repair_print_human(&rep);
            }
        }
        return rep.exit_code;
    }

    /* Non dry-run: actually truncate and seal as SALVAGE. */

    /* Always truncate to last_good_offset, even if it is already EOF.
       That removes any junk or partial frames beyond the salvageable prefix. */
    char trunc_err[256];
    if (truncate_file(path, last_good_offset, trunc_err, sizeof(trunc_err)) != 0) {
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "truncate failed: %s", trunc_err);
        rep.exit_code = FLASH_REPAIR_IO_ERROR;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    flash_seal_result fsr;
    int s_rc = flash_seal_append_fsig(
        path,
        FLASH_SEAL_SALVAGE,
        reason,
        chain_tip,
        record_count,
        &fsr
    );
    if (s_rc != 0) {
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "flash_seal_append_fsig() failed (rc=%d)", s_rc);
        rep.exit_code = FLASH_REPAIR_INTERNAL_ERROR;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    /* Post-repair check: FSIG verify must pass. */
    int v_rc = flash_seal_verify(path);
    if (v_rc != 0) {
        snprintf(rep.err_msg, sizeof(rep.err_msg),
                 "post-repair flash_seal_verify() failed (rc=%d)", v_rc);
        rep.exit_code = FLASH_REPAIR_INTERNAL_ERROR;

        if (!rep.quiet && rep.as_json) {
            flash_repair_print_json(&rep);
        } else if (!rep.quiet) {
            flash_repair_print_human(&rep);
        }
        return rep.exit_code;
    }

    rep.sealed_before = 0;
    rep.sealed_after = 1;
    rep.modified = 1;
    rep.exit_code = FLASH_REPAIR_OK;

    if (!rep.quiet) {
        if (rep.as_json) {
            flash_repair_print_json(&rep);
        } else {
            flash_repair_print_human(&rep);
        }
    }

    return rep.exit_code;
}
