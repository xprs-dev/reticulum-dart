# The file DHT — finding *who has a file*, with no central server

Aurora finds the providers of a content‑addressed file through a **Kademlia‑style
distributed hash table** that runs *over* Reticulum links. The code is in
[`lib/services/files/dht/`](../lib/services/files/dht/) and the node that drives
it is `FileTransferNode` ([`file_node.dart`](../lib/services/files/file_node.dart)).

This is the **find‑by‑hash** mechanism. (Find‑by‑*text* is a separate relay
index — see [file-sharing.md](file-sharing.md) §6.)

> **Why a DHT and not a server?** A provider record says "identity *P* holds file
> *H*". Storing those records at the DHT nodes *closest to H* means any node can
> find the holders of *H* by walking toward *H* in the keyspace — no node has the
> global picture, no server is privileged, and a provider that disappears simply
> stops republishing and ages out.

---

## 1. Keyspace, node IDs, distance

- **128‑bit keyspace**, matching Reticulum's destination‑hash width
  (`kDhtIdLen = 16`, `dht_core.dart`).
- A **node ID** is the node's RNS destination hash for the `geogram/dht`
  destination (`DhtContact.ofIdentity`).
- A **file's key** is the first 128 bits of its SHA‑256: `dhtFileKey(sha256) =
  sha256[:16]`.
- **Distance** is XOR, compared big‑endian (`dhtXor`, `dhtCompare`). The
  bucket index is the number of leading zero bits of the distance — closer nodes
  share a longer prefix.

## 2. Routing table — k‑buckets (`routing_table.dart`)

128 buckets (one per bit), each holding up to **k** contacts in
least‑recently‑seen → most‑recently‑seen order. On a full bucket the existing,
proven‑live contacts are kept and the newcomer is dropped (conservative under
churn).

**Liveness eviction.** Callers report each RPC's outcome via
`recordSuccess`/`recordFailure`; a contact that misses **`maxFailures` = 5**
RPCs in a row is evicted, so lookups stop paying a dead/unreachable peer's
timeout every round. Crucially, what counts as a failure is decided in
`file_node._dhtSendRpc`, not here: only an **unanswered FIND to a peer we had a
route to** counts. A no‑route skip (e.g. paths not yet warm at boot) is about
*our* routing, not the peer's liveness — counting it would evict the whole table
on startup before paths converge (observed, then fixed). A missing STORE ack
doesn't count either (it's often lost over multi‑hop even when the record
landed). Any reply resets the counter.

> **k is sized to cover the whole overlay, not the Kademlia default (8).**
> `FileTransferNode` constructs its `DhtNode` with **k = 96** and **α = 12**
> (both now `dhtK`/`dhtAlpha` constructor params, so they can be staged down
> without a library edit once the new‑code fleet is dense enough for replication —
> see §9), for a reason specific to how this overlay runs in the wild:
> replication STOREs to the k‑closest *routinely fail on public hubs* (§6), so a
> provider record usually lives **only on its holder**, which always keeps its own
> copy. A resolver therefore has to query the holder directly — but classic
> Kademlia only asks the *k closest to the key*. With k = 8 (or even 24) and a
> ~40‑node overlay, a chunk of peers — possibly including the sole holder — were
> **never queried**, so a fetch failed `no provider yet` for any key the holder
> wasn't XOR‑close to. Sizing k to span the overlay makes `resolve`/`publish`
> reach *every* known peer, so the holder is always among them; α = 12 fans each
> round out wide enough that this still finishes in a couple of rounds. This is
> the right trade only because the overlay is small (tens of nodes); a large
> overlay would need working replication instead (§9).

## 3. RPC protocol (`dht_message.dart`)

A compact **binary** encoding (not JSON/msgpack). Every message carries the
sender's 64‑byte public key so the receiver can learn it as a contact:

```
[op:1] [senderPub:64] [payload…]
```

| Op | Code | Payload | Response |
|----|------|---------|----------|
| `PING` | 0x01 | — | `PONG` (0x81) |
| `FIND_NODE` | 0x02 | target id (16 B) | `NODES` (0x82): up to N×64‑byte pubkeys |
| `FIND_VALUE` | 0x03 | sha256 (32 B) | `VALUE` (0x83): provider records **or** nodes |
| `STORE` | 0x04 | provider record | `STORE_OK` (0x84): bool |

Replies fit **one link‑encrypted packet**, sized to the link's negotiated MTU:
the floor is 5 contacts / 2 records (`kDhtWireMaxContacts`, `kDhtWireMaxRecords`,
a 500‑MTU packet), but a large‑MTU chat/TCP link (the DHT link does MTU discovery,
§4) carries up to 64 contacts / 16 records in one packet — fewer rounds on wide
lookups (`file_node._onDhtServePacket` computes the cap from `link.mtu` and passes
it to `handle`). No multi‑packet framing needed; the routing table still holds the
full k internally (§2) and just truncates what it puts on the wire.

## 4. Transport binding — DHT over Reticulum links (`file_node.dart`)

Each RPC is a short‑lived **Reticulum link** to the peer's **RPC destination**.
By default that is `geogram/dht`, but `FileTransferNode` takes `rpcApp`/
`rpcAspects` config and Aurora points it at the **chat** destination
(`geogram/chat`) — because the dedicated dht announce is dropped by the hubs'
announce budget, leaving no transport path to it, while the chat announce
propagates reliably (§8, §9). The Kademlia node id is still derived from
`geogram/dht` locally and is unaffected. We accept DHT links **only** on the RPC
dest (the legacy dht dest is never dialled nor announced — this is a fresh
deployment, no old-node interop). Every link frame carries a **1‑byte type tag**
(`0x01` = DHT) so the chat dest can be shared with future tenants without
collision: a non‑DHT frame is ignored. The shape below is the request/reply over
that link:

```
_dhtRpcRaw(peer, reqBytes):
  hop = ensurePath(peer, "geogram", ["dht"], maxPolls: 10)  // ~3 s path wait
  if hop == null: return null             // no route → SKIP this contact fast
  link = RnsLink.initiator(peer, "geogram", ["dht"])
  link.nextHop = hop                      // route via the learned hub if needed
  send(link.buildRequest())               // LINKREQUEST
  …on proof, send link.encrypt(reqBytes)  // the DHT message, encrypted
  await one encrypted reply (6 s timeout)
```

> **Skip‑fast matters for lookup latency.** A DHT lookup queries many contacts
> and tolerates individual misses, so it must *not* spend the ~9 s path budget a
> file fetch uses. When there is no route to a contact's `geogram/dht`
> destination, `_dhtRpcRaw` returns immediately instead of broadcasting a doomed
> link request and waiting out the handshake. Before this fix, every stale
> contact cost ≈9 s (path) + 8 s (handshake), and a resolve walking ~40 of them
> took **minutes**; now a dead contact costs ≈3 s and live ones answer in one
> RTT.

The responder side (`_acceptDhtLink` / `_onDhtServePacket`) accepts the link,
decrypts the request, hands it to `DhtNode.handleEncoded`, and returns the
encrypted response on the same link. So **every DHT message is end‑to‑end
encrypted** and addressed to a public‑key destination — there is no plaintext
tracker.

## 5. Provider records (`provider_record.dart`)

A signed "I provide this file" record:

```
{ sha256(32), providerPub(64), capacity, manifestHash?(32),
  timestampMs, ttlSec, signature(64) }
```

- **Signed (Ed25519) by the provider's identity** — any node can verify it
  without trusting whoever relayed it. (And since downloads are hash‑verified, a
  lying record costs only a wasted round trip.)
- Carries the provider's **public key**, which is both the verification key *and*
  the address to reach its `geogram/files` destination.
- **TTL = 2700 s (45 min)**; republished **every 30 min** (`rns_service.dart`).
  Abrupt departures self‑heal: a record nobody republishes simply expires.
- **Capacity class** (archive / home‑fibre / home‑wifi / wifi‑transient /
  cellular / BLE / unknown) lets resolvers prefer always‑on holders over a phone
  that may vanish.

## 6. Publish — becoming a provider (`DhtNode.publish`)

```
publish(record):
  closest = iterativeFindNode(record.fileKey)   // k nodes nearest the file key
  await Future.wait(closest.map STORE(record))   // fan out CONCURRENTLY
  ok = count(STORE_OK)
  always also store locally (we are authoritative for content we hold);
  if ok == 0: ok = 1   // we count as a holder of our own record
```

`FileTransferNode.publishProvider(sha256)` builds and signs the record then
publishes it, **and remembers it for the 30‑minute republish loop**. It is gated
by the serve quota: a node that can't currently serve doesn't advertise, so
resolvers route around it until it recovers. (Folder *keys* and other metadata go
through `publishKey`, which is **not** quota‑gated and lands in a separate
`_providedKeys` map — so the status field `provided`, which counts only
`_provided`, reads 0 on a node that is in fact advertising folders. That zero is a
red herring, not a bug.)

> **Two STORE fixes learned the hard way.** (a) The fan‑out is **parallel**: when
> it was a sequential `for` loop, one slow/dead contact's link handshake stalled
> every STORE behind it, and the hosted‑folder advertiser (which time‑bounds each
> publish at 10 s) cut replication off after the local copy only. (b) The
> publisher **always keeps its own record**, even when every replication STORE
> fails — otherwise a node with peers but flaky paths replicated to nobody *and*
> kept nothing, making content it was literally holding undiscoverable.
>
> **Reality check:** on the live public‑hub mesh, publish still typically logs
> `-> 1 holders (+self)` — replication to peers fails because there is no
> transport path to their `geogram/dht` destination (§9). Discovery works anyway
> because the holder keeps its own copy and resolve is sized to reach it (§2, §7).

Exposed to the app as `RnsService.dhtPublish(fileHash)`. This is called when you
**attach** a file *and* — now — whenever you **finish downloading** one (see
[file-sharing.md](file-sharing.md) §5), which is what makes every holder a
seeder.

## 7. Resolve — finding providers (`DhtNode.resolve`)

```
resolve(sha256):
  target = sha256[:16]
  seed found{} with any live local records
  iterate (α=12 in parallel, up to 24 rounds):
    FIND_VALUE(sha256) to the closest unqueried contacts
    on VALUE: verify signature, drop expired/mismatched, dedup by providerPub
    on NODES: add to the shortlist, keep walking toward target
    EARLY‑EXIT: stop the instant this round produced a verified record
  return providers sorted by capacity (best first)
```

> **FIND_VALUE short‑circuits.** Classic Kademlia FIND_VALUE returns as soon as a
> node hands back the value; ours did not — `_iterate` walked the *entire*
> shortlist (timeout per stale contact) even after the record was already in
> hand. Combined with the per‑contact cost in §4, a `resolve` that found the
> holder on round 1 still ground on for the rest of the k contacts — the
> multi‑minute "check for updates" hang. Now the lookup stops the moment any
> queried node returns a verified record (we keep the whole round that found it,
> so a resolver still gets a few providers for redundancy).

`FileTransferNode.resolveAndFetch` then tries the resolved providers in turn,
verifying the bytes against the hash. **Dead‑holder pruning:** if a provider fails
to serve, `DhtNode.demoteProvider` drops its record from our local store, so the
next resolve — here, or by a peer that queries us — doesn't waste a round on it.
The provider re‑publishes (~30 min) to come back, so a transient failure
self‑heals; across the mesh this prunes dead holders as fetches hit them. It is
the provider‑record counterpart to contact eviction (§2).

Exposed as `RnsService.dhtResolveFetch(fileHash)`.

> **Overlay empty / `publish -> 0 holders` / can't find a peer's files?** The
> usual cause is the two nodes landed on different hubs that don't bridge — see
> [peer-discovery.md](peer-discovery.md) for the mesh/reconnect/path checklist and a
> diagnostic recipe. It is (almost) never NAT.

## 8. Bootstrapping & membership — "which nodes run our DHT?"

There is no dedicated bootstrap server, and there is no global registry of "Aurora
nodes". This raises a real question, because **Aurora is (currently) the only
overlay running a DHT on Reticulum** — a public hub is full of Sideband,
NomadNet and `rnsd` identities that do *not* run it. How does a node tell which
peers can actually answer a DHT RPC?

**The answer is the destination name, proven by the signed announce.** Every
Reticulum announce advertises a *named destination* and is Ed25519‑signed; the
destination hash cryptographically binds the name to the announcing identity
(`dest_hash = sha256(name_hash || identity_hash)[:16]`, see
[reticulum.md](reticulum.md) §2). An Aurora node announces `geogram` destinations
(`geogram/files`, `geogram/chat`, …) that no other software announces, so their
`name_hash` is unique to our overlay. (We no longer announce `geogram/dht` itself —
DHT RPC rides the chat dest, §4 — but the id is still derived from it locally.)

So membership is a wire test, not a guess (`rns_service.dart`, `_onInbound`). A
peer is added to the routing table when we hear **any** of its signed `geogram`
announces — and we match on `geogram/dht`, `geogram/files`, *and* the
`geogram/chat` announce:

```dart
final dhtHash   = RnsDestination.hash(ann.identity, 'geogram', ['dht']);
final filesHash = RnsDestination.hash(ann.identity, 'geogram', ['files']);
if (constantTimeEquals(ann.destHash, dhtHash) ||
    constantTimeEquals(ann.destHash, filesHash)) {
  _files?.addPeerFromAnnounce(ann.identity);   // confirmed overlay node
}
…
final chatHash = RnsDestination.hash(ann.identity, 'geogram', ['chat']);
if (constantTimeEquals(ann.destHash, chatHash)) {
  _files?.addPeerFromAnnounce(ann.identity);   // chat announce ⇒ also a DHT member
}
```

A contact's DHT id is derived from its **identity**, not from which destination
we heard — so any proven `geogram` announce is enough to add it. We deliberately
accept the **chat** announce too, and that is a lesson from the field: **public
hubs rate‑limit announce propagation**, and the dedicated `geogram/dht` announce
is frequently the one that gets dropped while the same node's `chat` announce
(the most frequently sent, most reliably flooded one) gets through. Keying
overlay membership *only* off `geogram/dht` was fragile — peers whose dht announce
was dropped never joined the overlay and folder/file discovery silently failed.
Matching any `geogram` destination is still a cryptographic identity↔name proof,
so non‑Aurora identities (Sideband/NomadNet/`rnsd`, which never announce a
`geogram` name) are still never added.

Every Aurora node re‑announces its service destinations on an adaptive cadence
(30 s when charging on Wi‑Fi/Ethernet, 5 min on battery/cellular — see
[reticulum.md](reticulum.md) §3), so the table fills within an announce cycle of a
peer coming into view; on a hub with no other Aurora nodes it simply stays empty
and `resolve` returns nothing immediately instead of timing out on dead contacts.

> **Knowing a peer ≠ being able to route to its DHT dest — so we route to its
> chat dest.** Adding a contact from its chat announce gives us its identity
> (hence its DHT id), and a transport path to its **chat** dest. The dedicated
> `geogram/dht` dest is a *different* destination hash whose announce the hubs may
> have dropped, leaving no path to it — historically why replication STOREs failed.
> Aurora now runs the DHT RPC over the chat dest we already have a route to (§4),
> closing that gap; `_dhtRpcRaw` still skips a contact fast when even the configured
> RPC dest has no route resolved.

The same pattern identifies peers for the other overlays — the relay
(`geogram/relay`), LXMF (`lxmf/delivery`), files (`geogram/files`) — each by its own
announced destination name.

## 9. Honest limitations

- **Replication (historically the big one) — now addressed by routing RPC over
  chat.** STOREs to a peer's `geogram/dht` dest failed because there was no
  transport path to it (its dedicated dht announce was dropped by the hubs'
  announce budget, §8), so a provider record lived **only on its holder**. The fix
  (§4): run the DHT RPC over the **reliably‑propagated `geogram/chat`
  destination**, so any peer reachable for chat is reachable for DHT and STOREs
  land on the k‑closest. The holder‑keeps‑own‑record + k‑spans‑overlay safety nets
  (§2, §6, §7) remain as belt‑and‑braces. Two follow‑ups are intentionally *not*
  yet done: stop announcing `geogram/dht` (a release after dual‑accept is
  everywhere), and relax `k`/`alpha` back toward Kademlia norms once replication is
  confirmed landing on the live mesh.
- **Reply size caps** (5 contacts / 2 records per packet) mean wide result sets
  take extra rounds; there is no multi‑packet framing yet.
- **Store anti‑abuse caps.** Routing RPC over the (widely‑known) chat dest means
  any peer can open a DHT link and STORE at us, so the local store is bounded:
  at most `maxStoredKeys` distinct keys and `maxRecordsPerKey` providers per key
  (`DhtNode`). An over‑cap STORE is rejected BEFORE the Ed25519 verify, so a flood
  can't burn CPU or memory once we're full; a refresh of a record we already hold
  is always allowed (it doesn't grow the store). The `dhtRejected` status counter
  exposes refusals. Residual gap: rapidly *refreshing* an already‑held record
  still costs a re‑verify each time — a per‑peer rate limit would close that, not
  yet done.
- **Stale eviction** now removes a contact after 5 unanswered FINDs to a routable
  peer (§2), so the covered set trims to live nodes — but a peer we keep hearing
  announces from is re‑added, so on a quiet node (few lookups) the trim is gradual
  rather than aggressive; skip‑fast (§4) keeps the residual cost low.
- **On a large *foreign* public testnet**, the XOR‑closest nodes to a file key
  are reference RNS nodes that don't run this overlay and ignore the STORE/FIND
  RPCs — another reason replication can't rely on "the k closest to the key" and
  why k spans our own overlay instead. When a **sender is known** (chat media:
  you learned its route from its chat announce, and it is by definition a
  holder), the fetch goes **direct to that sender** and skips the DHT entirely.
  Content with **no known sender** — a folder/update file discovered by hash — is
  resolved through the DHT as above.

## 10. Validated end‑to‑end: the update flow

The decentralised app updater ([file-sharing.md](file-sharing.md),
`update_service.dart`) is the integration test for all of the above and is
**validated live between two devices on different networks**: a host publishes a
signed update folder; a phone that has *never seen* a freshly‑hosted build
discovers it (DHT resolve of the folder key → query the holder's relay for the
signed op‑log) in seconds, then fetches the binary by content hash over the same
DHT, verifies `sha256`, writes it, and re‑seeds it. Folder discovery queries the
resolved providers **concurrently with a short per‑provider timeout**
(`folder_relay.dart`) so a single stale/offline provider can't stall the check —
the same serial‑query‑times‑timeout trap that produced the original hang. See
[mutable-folders.md](mutable-folders.md) for the folder side.

## 11. Persistence anchors (capacity‑biased replication)

The XOR‑closest set is mostly **ephemeral** here (phones that sleep), so a record
can vanish on churn. To keep records alive on **always‑on** nodes without a wire
change, the DHT uses *persistence anchors*: a small, stable set of holders the
owner injects (`DhtNode.anchors`). Aurora feeds it the **relay indexers** from
`RelayDirectory` filtered to a stable capacity class (`capacity ≤ kCapHomeWifi`),
excluding self, top few by capacity/freshness — capacity is **already advertised**
on the relay announce, so nothing new goes on the wire.

- **`publish`** STOREs to the k‑closest **∪ anchors** (deduped) — records also
  live on the stable index nodes.
- **`resolve`** queries the anchors **first** (FIND_VALUE, in parallel) and
  returns on a verified hit; only if they don't have it does it fall back to the
  XOR‑walk. Anchors are queried **regardless of XOR distance or k**.

This decouples persistence and findability from XOR distance. Two consequences:
(a) records survive churn of the closest set; (b) it is the **enabler for shrinking
`k`** (§2) — once anchors guarantee findability, the XOR‑walk can use a small
Kademlia `k` as a secondary path. **Aurora runs `k=20`/`alpha=6`** on top of this
(the library default stays a safe `96`/`12` for consumers without anchors). Note:
anchors hold records for many keys, so an indexer reaches the anti‑abuse
`maxStoredKeys` cap (§9) sooner — a higher cap for indexers is a future knob (the
caps are already constructor params).

## 12. Completed follow-ups (this is a fresh deployment — no old-node interop)

The three items previously deferred are now done (no migration window to respect):

- **Stopped announcing `geogram/dht`** — DHT RPC rides the chat dest, so the dht
  dest is never dialled; `_announceServiceDests` no longer sends it (one fewer
  per-cycle announce → the others survive the hubs' budget more often). Membership
  comes from the chat/files announces (§8); the Kademlia id is still derived from
  `geogram/dht` locally. The legacy dual-accept and dht-dest fallback are removed —
  we accept DHT links only on the RPC dest.
- **MTU-aware reply sizing** (§3) — the DHT link does MTU discovery, and the FIND
  reply caps scale from the 5/2 floor up to 64 contacts / 16 records on a large-MTU
  link, cutting rounds on wide lookups.
- **Chat-dest type discriminator** (§4) — link frames carry a 1-byte type tag
  (`0x01` = DHT); non-DHT frames are ignored, reserving the chat dest for future
  tenants.

Residual: reply sizing only helps when the DHT link negotiates a large MTU (TCP
paths); BLE/500-MTU links keep the small caps. Indexers (anchors) hold records for
many keys, so they reach the `maxStoredKeys` cap (§9) sooner — a higher cap for
indexers remains a future knob (the caps are constructor params).
