# reticulum-dart

The shared **user + network protocol stack** for XPRS apps (Aurora and
others): a Dart implementation of the [Reticulum](https://reticulum.network/)
network, plus NOSTR identity & notes, LXMF messaging, a distributed NOSTR-style
relay, a DHT, content-addressed file sharing, the XPRS signature scheme, and
BLE transport primitives.

The goal is a single, reusable library so **different apps speak the same user
and network protocols** — share one identity, exchange messages, replicate
notes, move files, and reach peers over TCP/UDP/BLE — without re-implementing
any of it.

Shipped as a **Flutter package** (BLE needs platform plugins). The whole core —
Reticulum, NOSTR, LXMF, relay, DHT, files, XPRS — is plain Dart with no UI; only
the BLE transport pulls in Flutter, so the rest stays portable.

---

## What's inside

| Layer | Modules | What it does |
|------|---------|--------------|
| **Reticulum transport** | `RnsIdentity`, `RnsTransport`, `RnsLink`, `RnsPacket`, `RnsResource`, `RnsAnnounce`, `RnsCrypto`, HDLC framing | Wire-compatible Reticulum: addressable identities, announces, encrypted links, and chunked Resources. |
| **Interfaces** | `RnsTcpInterface`, `RnsTcpServerInterface`, `RnsUdpInterface`, `RnsAutoInterface` | Pluggable transports. (BLE and other radio interfaces are provided by the host app via the `RnsInterface` abstraction.) |
| **LXMF** | `LxmfMessage`, `LxmfRouter`, msgpack | Lightweight Extensible Message Format — store-and-forward messaging over Reticulum, interop-tested against the reference LXMF stack. |
| **NOSTR (user identity)** | `NostrCrypto`, `NostrEvent`, `NostrKeyPair`, `NostrKeyGenerator`, NIP-19 | secp256k1 / BIP-340 Schnorr keys, `npub`/`nsec` (bech32), signed events (kind-0 profiles, kind-1 notes, kind-3 follows), and a stable callsign derived from the npub. |
| **Social relay** | `RelayNode`, `RelayEventStore`, `RelayProtocol`, `RelayRole`/`RelayDirectory`, `FollowSet`, retention tiers, spam policy, store-and-forward | A distributed, NOSTR-style relay over Reticulum: an FTS-searchable event store, role/capacity announcements, follow sets, tiered retention and a deposit mailbox. |
| **DHT** | `DhtNode`, `DhtCore`, `RoutingTable`, `ProviderRecord` | Kademlia-style provider records so peers can find who holds a given hash. |
| **File sharing** | `FileNode`, `FileTransfer`, `FileManifest`, `MediaArchive`, `FileSource`/`CompositeFileSource`, serve quota/stats | Content-addressed (`file:<sha256>`) sharing: a local archive, a serve budget, and transfer over Reticulum Resources. |
| **XPRS signatures** | `xprs_crypto` | Compact (48-byte) secp256k1 Schnorr signatures over the same npub key — small enough to ride a single APRS line. |
| **BLE transport** (Flutter) | `RnsBleInterface`, `Ble5Radio`/bus, GATT client/server, parcel + reassembler | Reticulum over Bluetooth LE: connectionless BLE5 broadcast for short frames and GATT for larger transfers. The app provides its own BLE service that drives these. |

A single barrel exports everything:

```dart
import 'package:reticulum/reticulum.dart';
```

---

## Install

Depend on it by path (or git):

```yaml
dependencies:
  reticulum:
    path: ../reticulum-dart
  # or:
  # reticulum:
  #   git: { url: https://github.com/xprs-dev/reticulum-dart.git }
```

Then `flutter pub get`. `MediaArchive`, `RelayEventStore`, etc. use the
`sqlite3` package — add `sqlite3_flutter_libs` to your app for the native
library. BLE uses `bluetooth_low_energy` + `ble_peripheral`; declare the usual
Bluetooth/location permissions in your app.

---

## Quick start

### A NOSTR identity, signed notes

```dart
import 'package:reticulum/reticulum.dart';

final kp = NostrCrypto.generateKeyPair();
print(kp.npub);      // npub1…  (share this)
print(kp.callsign);  // X1xxxx  (stable short id derived from the npub)

final note = NostrEvent(
  pubkey: kp.publicKeyHex,
  createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
  kind: NostrEventKind.textNote,
  tags: const [['t', 'FEED']],
  content: 'hello from reticulum-dart',
)..sign(kp.privateKeyHex);

assert(note.verify());
```

### A Reticulum node on a TCP hub

```dart
import 'package:reticulum/reticulum.dart';

final id = await RnsIdentity.generate();
final transport = RnsTransport(log: print);

final tcp = RnsTcpInterface(
  host: 'rns.beleth.net',
  port: 4242,
  onPacket: (raw) {
    // route inbound packets — see doc/reticulum.md for announce/link handling
  },
);
transport.addInterface(tcp);
await tcp.connect();
```

The relay, LXMF router, DHT and file node are composed on top of a live
`RnsTransport` + `RnsIdentity`. See `doc/reticulum.md` for the full wiring, and
the Aurora app for a complete real-world integration (identity persistence,
capacity-gated hosting, BLE interface, etc.).

---

## Documentation

- [`doc/reticulum.md`](doc/reticulum.md) — the Reticulum stack: identities, announces, links, transport.
- [`doc/dht.md`](doc/dht.md) — the DHT and provider records.
- [`doc/file-sharing.md`](doc/file-sharing.md) — content-addressed file sharing.

---

## Status

Extracted from the Aurora app, which now consumes this package as its single
source of truth (device-validated across phones, Linux and an ESP32-S3 BLE5
node). The transport, NOSTR, LXMF and relay layers are in active use; treat the
API as **pre-1.0** (it may still move as the extraction settles). `flutter
analyze` is clean and the smoke tests pass (`flutter test`).

The host application is expected to provide: persistence paths, a power/network
capacity policy (to gate hosting), its own NOSTR profile/identity storage, and a
BLE service that drives the BLE transport primitives. The APRS protocol itself
lives in the XPRS APRS wapp (C/WASM); only its Dart signing (`xprs_crypto`) is
here.

## License

Apache-2.0. See [LICENSE](LICENSE).
