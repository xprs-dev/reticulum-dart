## 0.2.0

The package is plain Dart: it no longer depends on Flutter, so a server or a
command-line program can use it with `dart` alone.

- **Breaking:** `Ble5Bus`, `Ble5Radio`, `BleGattClient`, `BleGattServer` and
  `BleQueueService` moved to the new Flutter package `packages/reticulum_ble`
  (`import 'package:reticulum_ble/reticulum_ble.dart'`). `RnsBleInterface`,
  `BleParcel` and the reassembler stay here.
- Tests and tool harnesses use `package:test`; run them with `dart test`.

## 0.1.0

Initial extraction from the Aurora app into the shared XPRS protocol package.
Aurora now consumes this package as its single source of truth.

- Reticulum transport: identities, announces, links, resources, HDLC, TCP/UDP/auto interfaces.
- NOSTR identity & notes: secp256k1/Schnorr, bech32 npub/nsec, NIP-19, signed events.
- LXMF messaging.
- Distributed social relay: event store + FTS, roles/directory, follow set, retention tiers, spam, store-and-forward.
- DHT: provider records, routing table.
- Content-addressed file sharing: file node/transfer, media archive, serve quota/stats.
- XPRS compact (48-byte) Schnorr signatures.
- BLE transport primitives (BLE5 broadcast + GATT) via the RnsInterface abstraction (Flutter package).
