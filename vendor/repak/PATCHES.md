# Vendored repak Changes

Pak Merger uses a modified copy of `repak 0.2.3` from revision `e215472c51db69328b1ce77be2db24d24c1d646b`.

The local changes improve compression and decompression performance, reduce memory use for large files, add progress and error handling needed by the application, harden untrusted index parsing, correct UTF-16 mount-point offsets, and make the optional Oodle runtime download verified, bounded, cancellable, atomic, and retryable. Pak identifiers and the v11 output version are unchanged.
