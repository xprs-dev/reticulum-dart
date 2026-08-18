## 0.1.0

Initial extraction from the Aurora app into the shared geogram protocol package.
Aurora now consumes this package as its single source of truth.

- Reticulum transport: identities, announces, links, resources, HDLC, TCP/UDP/auto interfaces.
- NOSTR identity & notes: secp256k1/Schnorr, bech32 npub/nsec, NIP-19, signed events.
- LXMF messaging.
- Distributed social relay: event store + FTS, roles/directory, follow set, retention tiers, spam, store-and-forward.
- DHT: provider records, routing table.
- Content-addressed file sharing: file node/transfer, media archive, serve quota/stats.
- XPRS compact (48-byte) Schnorr signatures.
- BLE transport primitives (BLE5 broadcast + GATT) via the RnsInterface abstraction (Flutter package).
