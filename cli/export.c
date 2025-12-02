// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frf.h"
#include "flash/seal.h"

#ifndef EX_USAGE
#define EX_USAGE 64
#endif

static void export_usage(void) {
    fprintf(stderr,
        "usage: flash export [--output FILE] INPUT.flsh\n"
        "       Export a sealed+verified Flash record file as NDJSON.\n"
        "\n"
        "Options:\n"
        "  -o, --output FILE   Write NDJSON to FILE instead of stdout\n");
}

/* FSIG detection (taken from replay.c) */

#define FSIG_SEARCH_WINDOW 4096

static int detect_fsig_offset(const char* path,
                              int* has_fsig,
                              uint64_t* fsig_offset_out) {
    *has_fsig = 0;
    *fsig_offset_out = 0;

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr,
                "flash export: cannot open '%s' for FSIG scan: %s\n",
                path, strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr,
                "flash export: fseek end failed on '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0) {
        fprintf(stderr,
                "flash export: ftell failed on '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    if (size < 4) {
        fclose(f);
        return 0; // too small to contain "FSIG"
    }

    long window = size < FSIG_SEARCH_WINDOW ? size : FSIG_SEARCH_WINDOW;
    if (fseek(f, size - window, SEEK_SET) != 0) {
        fprintf(stderr,
                "flash export: fseek window failed on '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    unsigned char buf[FSIG_SEARCH_WINDOW];
    size_t n = fread(buf, 1, (size_t)window, f);
    fclose(f);

    if (n != (size_t)window) {
        // Short read; be conservative and just treat as unsealed
        return 0;
    }

    for (long i = 0; i <= window - 4; ++i) {
        if (buf[i] == 'F' && buf[i + 1] == 'S' &&
            buf[i + 2] == 'I' && buf[i + 3] == 'G') {
            *has_fsig = 1;
            *fsig_offset_out = (uint64_t)(size - window + i);
            return 0;
        }
    }

    // No FSIG magic found in the tail; treat as unsealed
    return 0;
}

/* export command */
int cmd_export(int argc, char** argv) {
    const char* input_path = NULL;
    const char* output_path = NULL;

    if (argc < 2) {
        export_usage();
        return EX_USAGE;
    }

    // Parse options + single positional input file
    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];

        if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr,
                        "flash export: missing FILE after %s\n", arg);
                export_usage();
                return EX_USAGE;
            }
            if (output_path) {
                fprintf(stderr,
                        "flash export: multiple -o/--output specified\n");
                return EX_USAGE;
            }
            output_path = argv[++i];
            continue;
        }

        if (arg[0] == '-') {
            fprintf(stderr,
                    "flash export: unknown option: %s\n", arg);
            export_usage();
            return EX_USAGE;
        }

        if (input_path) {
            fprintf(stderr,
                    "flash export: multiple INPUT files not supported\n");
            export_usage();
            return EX_USAGE;
        }
        input_path = arg;
    }

    if (!input_path) {
        fprintf(stderr, "flash export: missing INPUT.flsh\n");
        export_usage();
        return EX_USAGE;
    }

    /* Require sealed + verified (CLEAN or SALVAGE) */
    int vrc = flash_seal_verify(input_path);
    if (vrc == -2) {
        fprintf(stderr,
                "flash export: failed to open '%s' for verification: %s\n",
                input_path, strerror(errno));
        return 2;
    }
    if (vrc != 0) {
        fprintf(stderr,
                "flash export: '%s' is not sealed and fully verified.\n"
                "  Run 'flash verify %s' (or 'flash repair %s') first.\n",
                input_path, input_path, input_path);
        return 2;
    }

    /* Find FSIG trailer so we don't read into it */
    int has_fsig = 0;
    uint64_t fsig_offset = 0;
    if (detect_fsig_offset(input_path, &has_fsig, &fsig_offset) != 0) {
        // Error already printed
        return 2;
    }
    if (!has_fsig) {
        fprintf(stderr,
                "flash export: '%s' verified as sealed, but no FSIG trailer "
                "was found.\n"
                "  This should not happen; file may be malformed.\n",
                input_path);
        return 2;
    }

    /* Open output (default: stdout) */
    FILE* out = stdout;
    if (output_path) {
        out = fopen(output_path, "wb");
        if (!out) {
            fprintf(stderr,
                    "flash export: cannot open '%s' for writing: %s\n",
                    output_path, strerror(errno));
            return 2;
        }
    }

    /* Open FRF and verify header */
    frf_handle_t h;
    int rc = frf_open(input_path, "rb", &h);
    if (rc != 0) {
        fprintf(stderr,
                "flash export: failed to open '%s' as FRF (rc=%d)\n",
                input_path, rc);
        if (out && out != stdout) fclose(out);
        return 2;
    }

    frf_file_header_t fh;
    rc = frf_read_and_verify_header(&h, &fh);
    if (rc != 0) {
        fprintf(stderr,
                "flash export: '%s' is not a valid Flash record file "
                "(header rc=%d)\n",
                input_path, rc);
        frf_close(&h);
        if (out && out != stdout) fclose(out);
        return 2;
    }

    /* Stream frames from just after the header up to FSIG offset */
    uint64_t offset = FRF_FILE_HEADER_BYTES;
    unsigned char buf[64 * 1024];

    for (;;) {
        if (offset >= fsig_offset) {
            break; // stop before FSIG trailer
        }

        frf_record_header_t hdr;
        uint32_t payload_len = 0;

        rc = frf_next_record(&h, &hdr, buf, sizeof(buf), &payload_len);
        if (rc == 0) {
            uint64_t frame_bytes =
                (uint64_t)FRF_FRAME_OVERHEAD + (uint64_t)hdr.length;
            offset += frame_bytes;

            if (payload_len > 0) {
                size_t written = fwrite(buf, 1, payload_len, out);
                if (written != payload_len) {
                    fprintf(stderr,
                            "flash export: write to output failed (payload)\n");
                    frf_close(&h);
                    if (out && out != stdout) fclose(out);
                    return 2;
                }
            }

            if (fputc('\n', out) == EOF) {
                fprintf(stderr,
                        "flash export: write to output failed (newline)\n");
                frf_close(&h);
                if (out && out != stdout) fclose(out);
                return 2;
            }

            continue;
        }

        // Any nonzero rc here is real FRF corruption in the data section
        fprintf(stderr,
                "flash export: FRF error in '%s' (rc=%d). File may be corrupted.\n",
                input_path, rc);
        frf_close(&h);
        if (out && out != stdout) fclose(out);
        return 2;
    }

    frf_close(&h);
    if (out && out != stdout) {
        if (fflush(out) != 0) {
            fprintf(stderr,
                    "flash export: flush failed for '%s': %s\n",
                    output_path, strerror(errno));
            fclose(out);
            return 2;
        }
        fclose(out);
    } else {
        fflush(out);
    }

    return 0;
}
