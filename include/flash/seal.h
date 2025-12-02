// Copyright (c) 2025 Ryan King
// Licensed under the PolyForm Noncommercial License 1.0.0.
// See the LICENSE file for details.

#ifndef FLASH_SEAL_H
#define FLASH_SEAL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Seal modes mirror RUN_CLOSE status.
    typedef enum {
        FLASH_SEAL_CLEAN = 0, // normal clean close
        FLASH_SEAL_SALVAGE = 1 // truncated & sealed by repair
    } flash_seal_mode;

    // Optional reason codes for SALVAGE seals.
    typedef enum {
        FLASH_SALVAGE_OK = 0,
        FLASH_SALVAGE_PARTIAL_TRAILER = 1,
        FLASH_SALVAGE_CHAIN_FAIL = 2,
        FLASH_SALVAGE_CRC_FAIL = 3,
        FLASH_SALVAGE_MISSING_RUN_CLOSE = 4,
        FLASH_SALVAGE_NO_VALID_FRAMES = 5
    } flash_salvage_reason;

    // Result metadata returned by sealing.
    typedef struct {
        uint64_t signed_length; // bytes covered by digest/signature (EOF before trailer)
        uint64_t records; // frames/records kept
        uint8_t chain_tip[32]; // last frame hash from your BLAKE3 chain
        uint8_t kid[8]; // first 8 bytes of BLAKE2b-256(pubkey)
    } flash_seal_result;

    // Append a single FSIG trailer at EOF and fsync().
    // - path: file to seal (must already contain RUN_CLOSE on clean end)
    // - mode: CLEAN or SALVAGE
    // - reason: SALVAGE reason code (0 for CLEAN)
    // - chain_tip: 32-byte chain tip (BLAKE3-256) of the last valid frame
    // - records: total records in file
    // - out: optional result pointer (may be NULL)
    //
    // Returns 0 on success; negative on error.
    int flash_seal_append_fsig(const char* path,
                               flash_seal_mode mode,
                               int reason,
                               const uint8_t chain_tip[32],
                               uint64_t records,
                               flash_seal_result* out);

    // Verify the FSIG trailer and strict EOF.
    // Checks: trailer present, magic/version, algo ids, kid, digest, Ed25519 signature,
    // and that filesize == signed_length + trailer_size.
    int flash_seal_verify(const char* path);

#ifdef __cplusplus
}
#endif
#endif // FLASH_SEAL_H
