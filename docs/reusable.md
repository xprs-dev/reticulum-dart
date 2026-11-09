# Reusable code in reticulum-dart

Pieces worth reusing before writing new code. Keep this list current.

## Storage (zxdb)

- `openDb(path, {durable})` — `lib/src/util/db_opener.dart`. Every store opens
  through it: `:memory:` goes to `dbMemoryOpener`, anything else to the
  host-injectable `dbOpener` (XPRS core sets it to `openStoreDb`, which applies
  the profile's store secret). Never call `ZxSqlDb.open` directly in a store.
- `ZxSqlDb.transaction(fn)` — one commit for a batch; nested calls join the
  outer one. Each autocommit costs a generation (KBs of file, ms of time), so
  frequent writers batch (see `ServeStats`' buffered counters).
- `ZxSqlDb.textIndex(name, fields)` — full-text search (BM25) kept in the
  caller's transaction; used by `RelayEventStore` (`events`) and
  `MediaArchive` (`media`). Replaces SQLite FTS5.
- `MediaArchive.partsOf(db, key)` — a held file's bytes, one 256 KiB piece at
  a time, for workers that copy a large file out (XPRS core's
  `folder_export_io`) without putting it all on the heap.
- `RelayEventStore._vk` pattern — an indexed column holding the value, or
  `h:` + SHA-256 when the value is longer than an index key may be.
