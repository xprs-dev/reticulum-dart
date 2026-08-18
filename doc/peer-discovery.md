# Making two devices find each other on Reticulum

This is the hard-won checklist for **device-to-device reachability** — what has to
be true for one Aurora node to discover and fetch from another over the public
internet (DHT lookups, folder discovery by key, file fetch, relay queries). It was
derived by debugging "the wapp store can't see the folder hosted on the phone" to
a working device-to-device fetch over the internet, and it exists so we never
repeat that process.

Read alongside [reticulum.md](reticulum.md) (transport/links), [dht.md](dht.md)
(who-has-a-file), and [file-sharing.md](file-sharing.md).

---

## TL;DR — the three requirements

For node A to reach node B over the internet, ALL of these must hold:

1. **A and B share a transport hub.** Connect to *all* configured bootstrap hubs at
   once (a mesh), not first-reachable-wins. Different community hubs do **not**
   reliably bridge announces to each other, so if A picks hub X and B picks hub Y,
   they never meet.
2. **Both stay connected across network changes.** A hub uplink that dies (Wi-Fi⇄
   cellular, AP roam, hotspot switch) must be detected and re-dialed. RNS connects
   once at boot; without active reconnection a node sits dead with a stale "up".
3. **The path used for data is data-capable.** An announce-only interface (the LAN
   UDP discovery interface) must never shadow the hub path in the route table, or
   links to the peer time out.

If all three hold, the Aurora DHT overlay forms (each node hears one of the
other's signed `geogram` announces — `dht`, `files`, **or** `chat` — and adds it
as a routing-table contact; see [dht.md](dht.md) §8), `resolve` finds holders, and
links/fetches complete. (Note: provider records mostly do **not** replicate to
peers on the live mesh — no path to their `geogram/dht` dest — so discovery relies
on the holder keeping its own record and on `k` spanning the overlay; see
[dht.md](dht.md) §2, §9.)

## What is NOT the problem: NAT

Reticulum traverses NAT **by design**: a node behind carrier-grade NAT keeps an
*outbound* link to a transport hub, and the hub relays inbound traffic back over
that existing connection (reticulum.md §1, §4 — "Reachability across networks").
Two phones behind NAT can exchange data through a shared hub. "It must be NAT" is
the wrong diagnosis; the failures we hit were always one of the three requirements
above. Do not chase NAT.

---

## The failure modes we actually hit (and their symptoms)

| Symptom (logs / API) | Real cause | Fix |
|---|---|---|
| Host logs `RNS/files: publish <key> -> 0 holders` forever; consumer `folder/browse` returns 0 files | The two nodes are on **different hubs** that don't bridge; no Aurora peer is reachable to store/answer provider records | Mesh to all hubs (req. 1). After the fix the host logs `-> 1 holders` and resolve works |
| After the device changes network, `status.up` stays `true` but nothing flows; `RemoteApi: ... TCP interface not connected` | RNS connected once at boot and never reconnected; stale uplink | Auto-reconnect (req. 2) |
| Direct fetch by callsign times out: `RNS/files: files: fetch timeout` then `resolved 0 provider(s)`, even though announces arrive | The route to the peer is via an **announce-only LAN path** (no data) or the peer simply isn't reachable on a shared hub | Path-selection fix (req. 3) + mesh (req. 1) |
| Consumer only ever logs `rx from <peer> via lan`, never `via tcp` | The peer is on the **same LAN** (co-located). The LAN path forms but the hub data path doesn't (split-horizon) | Test internet discovery with the host OFF the LAN (see caveat) |

---

## How it works once the requirements hold

1. **Overlay membership** is by announce: a node is added to the DHT routing table
   when any of its signed `geogram` announces is heard — `dht`, `files`, or `chat`
   (rns_service.dart `_onInbound` → `_files.addPeerFromAnnounce`). The chat announce
   is included on purpose: hubs rate-limit announces and the dedicated `geogram/dht`
   one is often dropped, so keying membership only off it was fragile (see
   [dht.md](dht.md) §8). Confirm with `status.dhtPeers > 0`.
2. **Find a holder:** `DhtNode.resolve(key)` walks the routing table; a node answers
   `FIND_VALUE` with any provider record it holds **locally, regardless of XOR
   distance** (dht_node.dart). On a small overlay `closest()` returns *all* known
   Aurora peers, so a consumer that has the host in its table will query it and get
   the record. (For folders the key is the folderId pubkey; see
   [mutable-folders.md](mutable-folders.md).)
3. **Move the bytes:** a Link to the holder's `geogram/files` destination, carrying a
   Resource (reticulum.md §6–7). Every downloader re-publishes a provider record and
   re-serves — the swarm grows (file-sharing.md §5).

## The code that enforces the three requirements

1. **Mesh to all hubs** — `rns_autostart.dart` brings the node up on the first
   reachable hub via `RnsService.start()`, then calls `RnsService.connectUplink(host,
   port)` for every *other* configured hub; the 30s timer tops up any that dropped.
   `RnsService._connectedHubs` tracks held uplinks (idempotent). Keep the full
   bootstrap list in `preferences_service.dart` `_defaultRnsServers`.
2. **Auto-reconnect** — `RnsTcpInterface.onDisconnect` fires on socket close/error;
   `RnsService` also runs a **silence watchdog** (a live hub floods announces nonstop,
   so ~30s of total silence on the uplinks means the link is dead — catches network
   changes that kill the socket without a clean FIN). Either tears the dead uplink
   down (`_onUplinkDown`/`_allLinksDown`) and `rns_autostart`'s `onLinkDown` re-dials
   the mesh from the current network.
3. **Path selection** — `RnsInterface.announceOnly` (true only for
   `RnsLanInterface`, which drops all non-announce packets). In
   `RnsTransport.ingest`, a data-capable path always wins over an announce-only one
   regardless of hop count, and an announce-only ingest never overwrites a routable
   path. So a co-located LAN announce can't strand link traffic on a dead path.

## Important caveat: same-LAN co-location masks the test

If the host and consumer are on the **same LAN**, the consumer learns the host via
the announce-only LAN interface and may never form a hub data-path to it (the
consumer itself injects the host's LAN announce into the hub, so the hub doesn't
echo it back — split-horizon). Result: discovery fails *even though both are on the
same hub*. This is a **test artifact**, not the internet behaviour. **Always test
device-to-device discovery with the host on a genuinely different network** (e.g. a
phone on cellular/hotspot, off the desktop's Wi-Fi). Toggling the host's Wi-Fi to
"force" it off-LAN may just reconnect it to the same LAN — verify the host's IP is
on a different subnet first.

---

## Diagnostic recipe (remote API)

Drive each node's JSON API (`/api/rns/*`; phone via `adb forward tcp:<local> tcp:3456`).

1. **Both up and meshed?** `GET /api/rns/status` → `up:true`. In the log look for
   `added hub uplink <host> (mesh)` for each extra hub. Confirm both nodes list the
   *same* hub (e.g. `use.inertia.chat:4242`). Find a node's hub from the device:
   `adb shell cat /proc/net/tcp | awk '$4=="01" && $3 ~ /:1092$/'` (1092 = 4242).
2. **Overlay formed?** `status.dhtPeers > 0` on both. The host log should show
   `publish <key> -> 1+ holders` (not `-> 0 holders`).
3. **Do they hear each other over the hub?** Grep the consumer log for the host's
   identity hash with `via tcp` (not `via lan`). LAN-only sightings ⇒ co-located ⇒
   move the host off the LAN.
4. **Data link works?** `POST /api/rns/get {"sha256":"<hash>","from":"<host
   callsign>"}` → `{"ok":true,"len":…}` means a direct fetch over the hub succeeded.
5. **Folder discovery?** `POST /api/rns/folder/browse {"folderId":"<npub|hex>"}` →
   non-empty `files` (folder events resolved). It kicks an async refresh, so the
   first call may be empty — repeat after ~20s.
6. **Install path?** `POST /api/rns/folder/download {"folderId":…,"sha":…,"name":…}`
   → `{"ok":true}` fetched the bytes by hash over RNS.

## Surviving the host going offline — indexer auto-mirror (Phase 3)

Phones are intermittent (sleep, 5-min battery announce cadence, network changes), so a
folder hosted only on a phone vanishes when it sleeps. The fix is **always-on indexer
nodes that mirror** the folders they see, so they keep answering after the owner drops:

- **Self-nomination by capacity.** A node on mains power + Wi-Fi/Ethernet becomes a
  `RelayRole.indexer` (relay_role.dart `RelayAnnouncement.forCapacity`, gated on
  `profile.unlimited`). **A battery-less desktop/server counts as on-power** — the
  capacity governor treats `BatteryState.unknown`/no-battery as charging
  (capacity_governor.dart). Without that, an always-on desktop is misclassified as a
  leaf and never indexes. Leaf/battery nodes never mirror others' folders.
- **Auto-mirror on browse.** When an indexer host resolves a folder
  (`RnsService.folderBrowseAsync`), it auto-subscribes (auto-sync) to it. `folderBrowseAsync`
  already caches the signed folder events locally and re-advertises this node as a folder
  **provider** (`FolderRelay.publish`).
- **Background collation = the existing sync tick.** The 5-min `_autoSyncTimer` →
  `_autoSyncTick` (kept alive by the Android foreground service — reuse it, don't add a
  service) fully mirrors each subscribed folder for an indexer host: it downloads every
  file (not just changed ones, via `folderDownloadFile`/`folderFetchBytes`), which stores
  the bytes and **re-publishes provider records** for each sha. The 30-min DHT republish
  keeps those records (and the folder-key record) alive.

Net effect: once any always-on indexer has browsed a folder while the owner was up, it
holds the whole directory **and** the bytes and advertises as a provider. When the owner
sleeps, a consumer resolves the indexer by the folder key via the DHT (the same path used
to resolve the original host) and fetches from it. **Validated:** with the owner phone
force-stopped, a desktop indexer (relayRole=indexer, `provided=15`) still served the full
15-entry folder. Run two+ such indexers and there is no single point of failure (the
mirror is key-free and read-only — it cannot edit the folder; see
[mutable-folders.md](mutable-folders.md)).

For a folder that must ALWAYS be findable, ensure at least one always-on indexer has it in
its subscription set (it will, automatically, after browsing it once).
