// Flash FSIG sealing core (Ed25519 + BLAKE2b-256, Monocypher)
// This uses two external dependencies, Monocypher and libc.
// Writes exactly one fixed-size trailer at EOF and fsyncs.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "flash/seal.h"

// Monocypher
#include "third_party/monocypher/monocypher.h"

// Platform fsync & RNG shims
#if defined(_WIN32)
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #include <bcrypt.h>
  #if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
  static int fsync_file(FILE* f){ return _commit(_fileno(f)); }
  static int random_bytes(uint8_t* out, size_t n){
      NTSTATUS s = BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      return s == 0 ? 0 : -1;
  }
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <sys/random.h>
  static int fsync_file(FILE* f){ return fsync(fileno(f)); }
  static int random_bytes(uint8_t* out, size_t n){
      size_t off = 0;
      while (off < n) {
          ssize_t r = getrandom(out + off, n - off, 0);
          if (r < 0) { if (errno == EINTR) continue; return -1; }
          off += (size_t)r;
      }
      return 0;
  }
#endif

// Helpers
#define FSIG_MAGIC "FSIG"
#define FSIG_MAGIC_LEN 4
#define FSIG_VERSION 1
#define FSIG_ALGO_ED25519 1
#define FSIG_HASH_BLAKE2B_256 2

// Fixed trailer layout (little-endian, packed via manual stores)
// Total size: 200 bytes
enum { FSIG_TRAILER_SIZE = 200 };

static void wr_u32le(uint8_t* p, uint32_t v){
    p[0]=(uint8_t)(v); p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void wr_u64le(uint8_t* p, uint64_t v){
    p[0]=(uint8_t)(v); p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
    p[4]=(uint8_t)(v>>32); p[5]=(uint8_t)(v>>40); p[6]=(uint8_t)(v>>48); p[7]=(uint8_t)(v>>56);
}
static uint32_t rd_u32le(const uint8_t* p){
    return ((uint32_t)p[0]) | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t rd_u64le(const uint8_t* p){
    return ((uint64_t)rd_u32le(p)) | ((uint64_t)rd_u32le(p+4) << 32);
}

// Simple CRC32 (poly 0xEDB88320), for trailer integrity.
static uint32_t crc32(const uint8_t* data, size_t n){
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i=0;i<n;i++){
        c ^= data[i];
        for (int k=0;k<8;k++){ uint32_t m=-(c&1u); c=(c>>1)^(0xEDB88320u&m); }
    }
    return ~c;
}

// 64-bit tell helpers
static int64_t file_size_bytes(FILE* f){
#if defined(_WIN32)
    int64_t cur = _ftelli64(f);
    if (cur < 0) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) return -1;
    int64_t end = _ftelli64(f);
    if (_fseeki64(f, cur, SEEK_SET) != 0) return -1;
    return end;
#else
    off_t cur = ftello(f);
    if (cur < 0) return -1;
    if (fseeko(f, 0, SEEK_END) != 0) return -1;
    off_t end = ftello(f);
    if (fseeko(f, cur, SEEK_SET) != 0) return -1;
    return (int64_t)end;
#endif
}

// Compute BLAKE2b-256 over [0..EOF) of current file handle.
static int blake2b_file_digest(FILE* f, uint8_t out32[32], uint64_t* out_len){
    // Rewind
#if defined(_WIN32)
    if (_fseeki64(f, 0, SEEK_SET) != 0) return -1;
#else
    if (fseeko(f, 0, SEEK_SET) != 0) return -1;
#endif
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    uint8_t buf[1<<16];
    uint64_t total = 0;
    for(;;){
        size_t r = fread(buf, 1, sizeof(buf), f);
        if (r > 0){ crypto_blake2b_update(&ctx, buf, r); total += (uint64_t)r; }
        if (r < sizeof(buf)){
            if (ferror(f)) return -1;
            break;
        }
    }
    crypto_blake2b_final(&ctx, out32);
    if (out_len) *out_len = total;
    return 0;
}

// Build SigMsg = version|hash_id|signed_length|digest|chain_tip|seal_mode
// Returns length in bytes.
static size_t build_sigmsg(uint8_t* out, uint64_t signed_length,
                           const uint8_t digest[32],
                           const uint8_t chain_tip[32],
                           uint8_t seal_mode){
    uint8_t* p = out;
    // version (u32 le)
    wr_u32le(p, FSIG_VERSION); p += 4;
    // hash_id (u8)
    *p++ = (uint8_t)FSIG_HASH_BLAKE2B_256;
    // signed_length (u64 le)
    wr_u64le(p, signed_length); p += 8;
    // digest (32)
    memcpy(p, digest, 32); p += 32;
    // chain_tip (32)
    memcpy(p, chain_tip, 32); p += 32;
    // seal_mode (u8)
    *p++ = (uint8_t)seal_mode;
    return (size_t)(p - out);
}

// Derive KID = first 8 bytes of BLAKE2b-256(pubkey)
static void derive_kid(uint8_t kid[8], const uint8_t pubkey[32]){
    uint8_t h[32];
    crypto_blake2b(h, 32, pubkey, 32);
    memcpy(kid, h, 8);
    crypto_wipe(h, sizeof h);
}

// Public API

int flash_seal_append_fsig(const char* path,
                           flash_seal_mode mode,
                           int reason,
                           const uint8_t chain_tip[32],
                           uint64_t records,
                           flash_seal_result* out)
{
    int rc = -1;
    FILE* rf = fopen(path, "rb");
    if (!rf) return -2;

    // Compute digest over current file
    uint8_t digest[32];
    uint64_t signed_len = 0;
    if (blake2b_file_digest(rf, digest, &signed_len) != 0){ fclose(rf); return -3; }

    // Generate ephemeral Ed25519 keypair
    uint8_t seed[32];
    if (random_bytes(seed, sizeof seed) != 0){ fclose(rf); return -4; }
    uint8_t sk[64], pk[32];
    crypto_eddsa_key_pair(sk, pk, seed);
    crypto_wipe(seed, sizeof seed);

    // Build SigMsg and sign
    uint8_t sigmsg[4 + 1 + 8 + 32 + 32 + 1]; // 78 bytes
    size_t  sigmsg_len = build_sigmsg(sigmsg, signed_len, digest, chain_tip, (uint8_t)mode);

    uint8_t sig[64];
    crypto_eddsa_sign(sig, sk, sigmsg, sigmsg_len);

    // Build FSIG trailer in a single fixed buffer (200 bytes)
    uint8_t tr[FSIG_TRAILER_SIZE];
    uint8_t* p = tr;

    // magic "FSIG"
    memcpy(p, FSIG_MAGIC, FSIG_MAGIC_LEN); p += FSIG_MAGIC_LEN;
    // version, algo_id, hash_id, seal_mode, salvage_reason, 3 bytes reserved
    *p++ = (uint8_t)FSIG_VERSION;
    *p++ = (uint8_t)FSIG_ALGO_ED25519;
    *p++ = (uint8_t)FSIG_HASH_BLAKE2B_256;
    *p++ = (uint8_t)mode;
    *p++ = (uint8_t)((mode == FLASH_SEAL_SALVAGE) ? (uint8_t)reason : 0);
    *p++ = 0; *p++ = 0; *p++ = 0; // reserved

    // signed_length, records
    wr_u64le(p, signed_len); p += 8;
    wr_u64le(p, records); p += 8;

    // chain_tip, digest
    memcpy(p, chain_tip, 32); p += 32;
    memcpy(p, digest, 32);  p += 32;

    // pubkey, signature, kid
    memcpy(p, pk, 32);  p += 32;
    memcpy(p, sig, 64); p += 64;
    uint8_t kid[8]; derive_kid(kid, pk);
    memcpy(p, kid, 8);  p += 8;

    // trailer CRC over all previous trailer bytes
    uint32_t tcrc = crc32(tr, (size_t)(p - tr));
    wr_u32le(p, tcrc); p += 4;

    // Append trailer and fsync
    FILE* wf = fopen(path, "ab");
    if (!wf){ rc = -5; goto CLEANUP; }
    size_t w = fwrite(tr, 1, sizeof tr, wf);
    if (w != sizeof tr){ rc = -6; fclose(wf); goto CLEANUP; }
    fflush(wf);
    if (fsync_file(wf) != 0){ rc = -7; fclose(wf); goto CLEANUP; }
    fclose(wf);

    // Wipe secrets and return result
    crypto_wipe(sk, sizeof sk);
    crypto_wipe(sig, sizeof sig);

    if (out){
        out->signed_length = signed_len;
        out->records = records;
        memcpy(out->chain_tip, chain_tip, 32);
        memcpy(out->kid, kid, 8);
    }
    rc = 0;

CLEANUP:
    crypto_wipe(sk, sizeof sk);
    fclose(rf);
    return rc;
}

int flash_seal_verify(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f) return -2;

    // File must be at least trailer size
    int64_t fsz = file_size_bytes(f);
    if (fsz < 0 || (uint64_t)fsz < (uint64_t)FSIG_TRAILER_SIZE){ fclose(f); return -3; }

    // Read trailer
#if defined(_WIN32)
    if (_fseeki64(f, (int64_t)fsz - FSIG_TRAILER_SIZE, SEEK_SET) != 0){ fclose(f); return -4; }
#else
    if (fseeko(f, (off_t)(fsz - FSIG_TRAILER_SIZE), SEEK_SET) != 0){ fclose(f); return -4; }
#endif
    uint8_t tr[FSIG_TRAILER_SIZE];
    if (fread(tr, 1, sizeof tr, f) != sizeof tr){ fclose(f); return -5; }

    // Check magic
    if (memcmp(tr + 0, FSIG_MAGIC, FSIG_MAGIC_LEN) != 0){ fclose(f); return -6; }

    // CRC check
    uint32_t tcrc_stored = rd_u32le(tr + (FSIG_TRAILER_SIZE - 4));
    uint32_t tcrc_calc = crc32(tr, FSIG_TRAILER_SIZE - 4);
    if (tcrc_calc != tcrc_stored){ fclose(f); return -7; }

    uint8_t version = tr[4];
    uint8_t algo_id = tr[5];
    uint8_t hash_id = tr[6];
    uint8_t seal_mode = tr[7];
    (void)seal_mode;
    // tr[8] = salvage_reason (optional); tr[9..11] reserved

    if (version != FSIG_VERSION || algo_id != FSIG_ALGO_ED25519 || hash_id != FSIG_HASH_BLAKE2B_256){
        fclose(f); return -8;
    }

    uint64_t signed_len  = rd_u64le(tr + 12);
    /* uint64_t records  = rd_u64le(tr + 20); */ // available if needed
    const uint8_t* chain_tip = tr + 28; // 32 bytes
    (void)chain_tip; // not rechecked here
    const uint8_t* digest_tr = tr + 60; // 32 bytes
    const uint8_t* pk = tr + 92; // 32
    const uint8_t* sig = tr + 124; // 64
    const uint8_t* kid = tr + 188; // 8

    // Enforce strict EOF
    if (signed_len + FSIG_TRAILER_SIZE != (uint64_t)fsz){ fclose(f); return -9; }

    // Recompute digest over [0..signed_len)
#if defined(_WIN32)
    if (_fseeki64(f, 0, SEEK_SET) != 0){ fclose(f); return -10; }
#else
    if (fseeko(f, 0, SEEK_SET) != 0){ fclose(f); return -10; }
#endif
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    {
        uint8_t buf[1<<16];
        uint64_t left = signed_len;
        while (left){
            size_t chunk = left > sizeof(buf) ? sizeof(buf) : left;
            size_t r = fread(buf, 1, chunk, f);
            if (r != chunk){ fclose(f); return -11; }
            crypto_blake2b_update(&ctx, buf, r);
            left -= r;
        }
    }
    uint8_t digest_calc[32];
    crypto_blake2b_final(&ctx, digest_calc);
    if (crypto_verify32(digest_calc, digest_tr) != 0){ fclose(f); return -12; }

    // Verify KID
    uint8_t kid_calc[32];
    crypto_blake2b(kid_calc, 32, pk, 32);
    if (memcmp(kid_calc, kid, 8) != 0){ fclose(f); return -13; }

    // Verify signature over SigMsg(version, hash_id, signed_len, digest, chain_tip, seal_mode)
    uint8_t sigmsg[4 + 1 + 8 + 32 + 32 + 1];
    size_t sigmsg_len = build_sigmsg(sigmsg, signed_len, digest_tr, tr + 28, tr[7]);
    if (crypto_eddsa_check(sig, pk, sigmsg, sigmsg_len) != 0){ fclose(f); return -14; }

    fclose(f);
    return 0;
}
