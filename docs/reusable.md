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


## Requests over a link, gateways, the browser build (2026-11-10)

- **`RnsRequestServer` / `RnsRequestClient`** (`rns_request.dart`): RNS
  `Link.request` both sides. The server accepts links on one destination and
  answers by path (`register(path, handler)`); the client keeps one link and
  sends any number of requests, matching responses by request id. Anything
  past one packet rides a Resource, both ways, one at a time per link. Use it
  for any "call a service on a station" over Reticulum instead of a new
  framing (the relay node and the file node predate it).
- **`RnsFrameInterface`** (`rns_frame_interface.dart`): one packet per frame
  over anything message-shaped (a WebSocket), no dart:io; `quiet: true` keeps
  the announce flood and everything sent "on all" off it.
- **`RnsGatewayClient`** (`rns_gateway_client.dart`): a leaf node behind one
  frame interface: learns paths from the gateway's answers, hands out request
  clients. The browser build and `server/tool/gateway_probe.dart` both use it.
- **`RnsInterface.quiet`**: an interface that gets only what is addressed to
  it (its links, answers to its path requests).
- **The browser build**: `web/rns_browser.dart`, compiled by
  `tool/build_rns_js.sh` into `build/rns.js` (`XprsRns`: connect, resolve,
  open, prove, api, close). Import only platform-neutral files there (never
  `reticulum.dart`, which pulls dart:io). `RnsCrypto.ed25519Verify` verifies
  inline on the web (no isolates there); `test/web_crypto_test.dart` checks
  the crypto compiled to JavaScript, in Chromium (`-p chrome`, with
  `CHROME_EXECUTABLE=/usr/bin/chromium`).
