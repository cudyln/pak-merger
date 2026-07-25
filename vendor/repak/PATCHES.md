# Vendored repak Changes

Pak Merger uses a modified copy of `repak 0.2.3` from revision `e215472c51db69328b1ce77be2db24d24c1d646b`.

The local changes improve compression and decompression performance, reduce memory use for large files, add progress and error handling needed by the application, harden untrusted index parsing, correct UTF-16 mount-point offsets, and make the optional Oodle runtime download verified, bounded, cancellable, atomic, and retryable. Pak identifiers and the v11 output version are unchanged.

## Single-block compression block size (`repak/src/entry.rs`, `read_encoded`)

A compressed entry whose data fits in one block has no meaningful block size, so
UE's encoder stores `0` for it and the reader restores the uncompressed size
(`FPakEntry::Encode` / `FPakEntry::Decode`). Upstream `read_encoded` kept the
decoded value at `0`, which leaves the block layout undecodable.

UnrealPak takes that path for every file smaller than the Pak-wide compression
block size, so any compressed Pak built with UnrealPak failed to open — the
strict local-header cross-check reported "the file header for … disagrees with
the Pak file list", and forcing past it produced a decompression failure. The
format is irrelevant; Zlib and Oodle failed identically, and uncompressed Paks
were unaffected. repak's own writer escapes an unaligned block size with `0x3f`
instead of storing `0`, so Paks written by repak never exercised the case.

`read_encoded` now restores `compression_block_size = uncompressed_size` when a
compressed entry declares exactly one block and the encoded size is `0`.

The writer had the mirror-image problem: it recorded the Pak-wide
`layout.block_size` even when the entry compressed into a single block, so
UnrealPak rejected repak's own output with "PakEntry mismatch" for every small
file. `Entry::write_file`-style compression now records the uncompressed size as
the block size whenever `block_count == 1`, matching the engine. Multi-block
entries keep the Pak-wide value, and the encoded index form is unchanged.

Verified both directions on ten Paks — UnrealPak `none`/`Zlib`/`Oodle`, repak
`none`/`Oodle`, merged output, and the shipped mod releases: all open in both
readers, UnrealPak extracts every entry with zero mismatches, and the extracted
payloads are byte-identical across every producer and compression setting.
