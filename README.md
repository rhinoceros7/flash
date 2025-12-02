# Flash

Flash is a C library and unified CLI for working with append-only, verifiable event streams stored in `.flsh` files.

It is designed for high-throughput capture of time-ordered records (market data, telemetry, logs, etc.) with built-in integrity checks, a cryptographic seal, and a practical command-line workflow.

---

## Overview

At a high level, Flash gives you:

- **Flash Record Format (FRF):**
  - Files start with a fixed magic + version header.
  - The rest of the file is a sequence of time-ordered frames.
  - Each frame has a small header, a payload, and a link into a **BLAKE3 hash chain**.

- **Data vs control frames:**
  - FRF itself is type-agnostic.
  - A `type` field lets you treat some frames as data records and others as control/metadata.
  - The CLI and higher-level tooling layer the semantics on top.

- **Integrity and verifiability:**
  - Per-frame CRC32 checksums catch local corruption.
  - A rolling BLAKE3 hash chain ties frames together in order.
  - A final **FSIG trailer** (optional) can seal the file with:
    - A BLAKE2b-256 digest over the file contents.
    - The final hash-chain tip.
    - An Ed25519 signature and a small block of metadata.

- **Core library (`frf`):**
  - Framed I/O (read/write frames).
  - CRC + hash-chain maintenance.
  - Helpers for exposing the chain tip and other metadata to callers.

- **CLI tools:**
  - `flash ingest` - write new `.flsh` files from streams.
  - `flash verify` - check structure, hashes, and optional FSIG seal.
  - `flash repair` - salvage damaged files and reseal them as SALVAGE.
  - `flash index` - build sidecar index files for faster seeking.
  - `flash replay` - stream records back out with filters.
  - `flash merge` - combine multiple streams into a new file.
  - `flash export` - export verified files to NDJSON.
  - `flash info` - simple header/metadata inspection.

Flash is currently oriented around crypto / market data capture, but the format is general enough to be used anywhere you need append-only, timestamped records with replay and integrity built in.

---

## Status

Flash is experimental and still evolving.

- The magic/version header is fixed, but the on-disk format may still change.
- The CLI surface is stabilizing, but subcommands and flags are not guaranteed to be frozen yet.
- You should not treat this as a fully baked compliance/archive solution yet.

Use it, kick the tires, and expect some rough edges.

---

## Building

Flash is built with CMake and a C17-capable compiler.

### Requirements

- C compiler with C17 support (clang, gcc, MSVC, etc.)
- CMake 3.x
- A reasonably POSIX-like environment (Linux, macOS, WSL, or Windows with MSVC/MinGW)

All required crypto primitives are bundled (BLAKE3 and Monocypher), so you should not need to install extra libraries.

### Build steps

From the project root:

```sh
cmake -S . -B build
cmake --build build --config Release
```

This will produce a `flash` binary in `build/bin/`.

You can verify it is working with:

```sh
build/bin/flash --help
```

---

## Quickstart

Here is a minimal end-to-end example:

```sh
# 1) Ingest some lines from stdin into a new stream
printf 'one
two
' | build/bin/flash ingest demo.flsh from stdin as lines

# 2) Verify integrity (FRF scan and FSIG if present)
build/bin/flash verify demo.flsh

# 3) Replay records (raw and human-readable)
build/bin/flash replay demo.flsh
build/bin/flash replay demo.flsh --human

# 4) Export to NDJSON
build/bin/flash export demo.flsh > demo.ndjson
```

Exact options and subcommands are defined in the CLI sources, but the general flow is:

1. **Ingest** data into `.flsh`.
2. **Verify** the file.
3. **Replay** frames to inspect or feed into other tools.
4. **Export** to NDJSON when you want line-oriented JSON for downstream pipelines.

---

## Core concepts

### Files, runs, and frames

A `.flsh` file is made of:

- A header (magic, version, basic metadata).
- A sequence of frames, each with:
  - A small header (kind, length, timestamp, hash-chain link, etc.).
  - A payload (your data bytes).

Frames come in two broad flavors:

- **Data frames** - carry your application payloads.
- **Control frames** - carry metadata about the run, indexes, close markers, and so on.

Appends always go to the end of the file. There is no in-place update.

### Sealing

A typical lifecycle looks like this:

1. Start ingest - write header and initial control frames.
2. Stream data frames as records arrive.
3. Close the run.
4. Append an FSIG trailer that includes:
   - A digest of the file contents.
   - The final hash-chain tip.
   - Record counts and run status (CLEAN or SALVAGE).
   - An Ed25519 signature over a small summary structure.

Once sealed, the file is effectively immutable. `flash verify` can:

- Check all CRCs and hash links.
- Recompute the digest.
- Validate the signature against the embedded public key.

If anything has been tampered with, verification will fail.

### Salvage and repair

If a file is corrupted or truncated (for example, a crash mid-write), you can run:

```sh
build/bin/flash repair broken.flsh
```

`repair` will:

- Scan frames until it hits a structural or integrity error.
- Truncate the file to the last good frame (if required).
- Write a new FSIG trailer with a **SALVAGE** status and a small reason code.

You end up with a shorter file, but one that is cleanly sealed and verifiable. Downstream consumers can see from the metadata that the file was recovered, not clean.

### Indexes

For large files, scanning every frame to satisfy a query is slow. `flash index` builds a `.fidx` sidecar containing timestamp and offset information at a regular stride.

`flash replay` can then:

- Auto-load the index when present.
- Seek quickly to the portion of the file needed for a given time range.
- Fall back to a full scan if requested or if the index is missing.

---

## CLI overview

The `flash` binary is a single entry point with multiple subcommands.

### `ingest`

```sh
flash ingest OUT.flsh from <source> as <format> [options]
```

Create or append to a `.flsh` file by reading from a source in a given input format.

Typical patterns:

- `from stdin as lines` – newline-delimited text from stdin.
- `from file <path> as ndjson` – NDJSON file.
- Other sources and formats (files, dirs, network/HTTP streams, etc.) are available; see `flash ingest --help` for the full matrix.

Options let you:

- Label record types.
- Configure rotation (by size, time, or record count).
- Choose how strict the parser should be.

### `verify`

```sh
flash verify [options] FILE.flsh
```

Validate a `.flsh` file:

- Check FRF structure and per-frame CRCs.
- Validate the BLAKE3 hash chain.
- If an FSIG trailer is present, verify the digest and Ed25519 signature.
- Report whether the file is sealed and whether it was CLEAN or SALVAGE.

There is also a JSON output mode and quiet/verbose flags for scripting.

### `repair`

```sh
flash repair [options] FILE.flsh
```

Attempt to salvage a damaged file by truncating to the last valid frame and sealing it as SALVAGE.

- By default, performs the repair and writes a new FSIG trailer.
- Dry-run and JSON modes are available so you can inspect what would happen before modifying the file.

### `replay`

```sh
flash replay [options] FILE.flsh
```

Stream records back out in order. Useful options include:

- Time filters: `--from-ts`, `--to-ts`.
- Limit: `--limit N`.
- Output mode:
  - Default: raw payloads.
  - `--with-ts`: include timestamps.
  - `--data-only`: skip control frames.
  - `--human`: friendly summary view for humans.
  - `--no-trunc`: do not truncate large payloads in human mode.
- Index control: `--no-index` to force a full scan even if an index exists.

### `index`

```sh
flash index [options] FILE.flsh
```

Build or rebuild a `.fidx` index sidecar for a file.

- `--every=N` controls the stride (how often frames are indexed).
- Inspection flags let you print a summary of the index instead of building it.

### `merge`

```sh
flash merge OUT.flsh A.flsh B.flsh [...]
```

Merge multiple verified `.flsh` files into a new one.

- Ensures inputs are structurally valid before writing.
- Rebuilds the hash chain for the merged output.
- Seals the new file with a fresh FSIG trailer.

### `export`

```sh
flash export [options] INPUT.flsh
```

Export the payloads of a verified `.flsh` file as **NDJSON**.

- By default, writes to stdout.
- An `--output` flag allows writing directly to a file.
- Only sealed or successfully repaired files are exported.

### `info`

```sh
flash info FILE.flsh
```

Print a small summary of the file header and basic metadata.

This is intended as a quick sanity check / debugging helper and will likely grow over time.

---

## Use cases

A few concrete ways to use Flash:

- **Market data capture:**
  - Ingest order book updates and trades into hourly `.flsh` files.
  - Verify and seal them at the end of each run.
  - Use `replay` and `export` to drive backtests or simulations.

- **Telemetry and logs:**
  - Treat structured logs as events.
  - Store them in `.flsh` files with periodic rotation.
  - Use `verify` and `repair` to ensure archives are intact before analysis.

- **Event sourcing / audit trails:**
  - Capture business events in an append-only format.
  - Seal them with FSIG when a batch is complete.
  - Rely on the signature and hash chain as a tamper-evident audit trail.

---

## Roadmap

High-level areas that are likely to evolve:

- Richer `flash info` output (more metadata, nicer formatting).
- Additional export targets (for example, more structured formats on top of NDJSON).
- Performance tuning for very large files and high-throughput ingest.
- More examples and docs, including library-level usage from C.

As the format settles, the FRF spec and sealing rules will be documented more formally.

---

## Contributing

Contributions via issues and pull requests are welcome.

---

## License

Flash is made available under the PolyForm Noncommercial License 1.0.0.

This means you may use, modify, and share the software for personal,
academic, experimental, and other noncommercial purposes. Commercial use of
any kind is strictly prohibited without a separate commercial license from
the author.

For full terms, see the LICENSE file.
