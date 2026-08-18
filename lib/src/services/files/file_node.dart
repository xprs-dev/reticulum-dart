/*
 * FileTransferNode — wires the file-transfer sessions to a live Reticulum
 * transport. It is the per-node hub that:
 *   - serves files: accepts inbound LINKREQUESTs to our "files" destination,
 *     completes the link handshake (responder), and runs a FileServeSession that
 *     answers GET_MANIFEST/GET_CHUNK from a FileSource;
 *   - fetches files: opens a link to a provider's "files" destination (initiator),
 *     then runs a FileFetchSession to pull + verify a file by its sha256.
 *
 * Transport-agnostic: the owner supplies a [send] callback (e.g.
 * transport.sendLinkAware) and feeds inbound packets to [handlePacket]. Link/file
 * packets are addressed by link_id; the transport routes established-link traffic
 * on the interface the link's proof arrived on (noteLinkIface), and the LAN lane
 * unicasts to the learned peer.
 */
import 'dart:async';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../reticulum/rns_crypto.dart';
import '../reticulum/rns_identity.dart';
import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import 'dht/dht_core.dart';
import 'dht/dht_message.dart';
import 'dht/holder_hint.dart';
import 'dht/dht_node.dart';
import 'dht/provider_record.dart';
import 'file_transfer.dart';
import 'partial_store.dart';
import '../../util/npd.dart';
import 'serve_quota.dart';

const String kFilesApp = 'xprs';
const List<String> kFilesAspects = ['files'];

class _ServeEntry {
  final RnsLink link;
  final FileServeSession serve;
  Uint8List? proof; // cached LRPROOF bytes, replayed on a repeated request
  _ServeEntry(this.link, this.serve);
}

class _FetchEntry {
  final RnsLink link;
  final Uint8List fileHash;
  final Completer<Uint8List?> done;
  FileFetchSession? fetch; // null until the link is active
  Uint8List? rttRaw; // our LRRTT (re-sent if the responder re-proofs)
  Timer? timeout;
  Timer? retry; // periodic stall-recovery (re-request missing parts)
  Duration baseTimeout = const Duration(minutes: 20);
  // Resume bookkeeping: whether this attempt started in resume mode, whether we
  // already fell back to a full fetch on this link, and a serial chain so
  // completed segments persist to the PartialStore in order.
  bool resumeUsed = false;
  bool restartedFull = false;
  Future<void> persist = Future.value();
  _FetchEntry(this.link, this.fileHash, this.done);
}

/// One peer of a piece swarm: a link held open, serving one request at a time.
class _PieceEntry {
  final RnsLink link;
  final PieceFetchSession session;
  Uint8List? rttRaw;
  Completer<bool>? ready; // completes when the link handshake finishes
  Completer<void>? pending; // completes when the current request settles
  Timer? retry;
  bool dead = false;
  int served = 0; // pieces this peer actually delivered (for a fair ranking)
  _PieceEntry(this.link, this.session);
}

class _DhtRpcEntry {
  final RnsLink link;
  final Uint8List reqBytes;
  final Completer<Uint8List?> done = Completer<Uint8List?>();
  bool sent = false; // request sent (link active)
  _DhtRpcEntry(this.link, this.reqBytes);
}

class _DepositEntry {
  final RnsLink link;
  final Uint8List sha;
  final Uint8List bytes;
  final String ext;
  final Uint8List pub;
  final Uint8List sig;
  final Completer<bool> done;
  FileDepositSession? dep; // null until the link is active
  Timer? timeout;
  _DepositEntry(
      this.link, this.sha, this.bytes, this.ext, this.pub, this.sig, this.done);
}

class _Provided {
  final Uint8List sha;
  final int capacity;
  final Uint8List? manifestHash;
  _Provided(this.sha, this.capacity, this.manifestHash);
}

class FileTransferNode {
  final RnsIdentity identity; // our identity (must hold private keys)
  final FileSource source; // what we serve
  final void Function(Uint8List raw) send; // e.g. transport.sendOnAll
  final void Function(String msg)? log;

  late final Uint8List filesDestHash =
      RnsDestination.hash(identity, kFilesApp, kFilesAspects);
  late final Uint8List dhtDestHash =
      RnsDestination.hash(identity, kDhtApp, kDhtAspects);

  /// The destination DHT RPC links ride over. Defaults to the dedicated
  /// xprs/dht dest, but the host can point it at a more reliably-announced
  /// destination (e.g. the chat dest) so RPC links route where transport paths
  /// actually exist — public hubs drop the dedicated xprs/dht announce,
  /// leaving no path to it, so STOREs to peers never land. The Kademlia node id
  /// (DhtContact.id) is unaffected: it is still derived from the xprs/dht dest
  /// locally and never needs a path or an announce.
  final String rpcApp;
  final List<String> rpcAspects;
  late final Uint8List rpcDestHash =
      RnsDestination.hash(identity, rpcApp, rpcAspects);

  /// Another tenant sharing the RPC (chat) destination: a link frame tagged for
  /// it (not [_kDhtFrame]) is handed here and the returned bytes are tagged back
  /// and sent as the reply. Aurora wires this to the relay node so relay REQ/EVENT
  /// /SYNC links ride the same reliably-pathed chat dest without a second dest.
  /// The tag is [_kRelayFrame]; null = no other tenant (frame dropped as today).
  Future<Uint8List?> Function(Uint8List relayBody)? onRelayFrame;

  /// Persists segment-aligned partial downloads so a fetch resumes after a drop
  /// or app restart (generic — every fetch consumer benefits). Null = no resume
  /// (today's in-memory, all-or-nothing behaviour).
  final PartialStore? partialStore;

  final Map<String, _ServeEntry> _serve = {}; // link_id hex -> serve
  final Map<String, _FetchEntry> _fetch = {}; // link_id hex -> fetch
  final Map<String, _PieceEntry> _pieces = {}; // link_id hex -> piece peer
  // Coalesce concurrent fetches of the SAME file (content-addressed) so two
  // callers can't race the same .part / open competing links.
  final Map<String, Future<Uint8List?>> _inflightBySha = {};
  // DHT links: responder links we host, and in-flight outbound RPC links.
  final Map<String, RnsLink> _dhtServeLinks = {};
  final List<String> _dhtServeOrder = [];
  // Packed LRPROOF per served link-id, so a duplicate LINKREQUEST is answered
  // from cache instead of re-signing. Evicted alongside _dhtServeLinks.
  final Map<String, Uint8List> _dhtServeProofs = {};
  final Map<String, _DhtRpcEntry> _dhtRpcByLink = {};
  static const int _maxDhtServeLinks = 128;
  // Live download progress for the UI: file sha hex -> (received, total) bytes,
  // updated as a fetch advances and cleared when it ends (total 0 = indeterminate).
  final Map<String, ({int received, int total})> _fetchProgress = {};
  // Files we advertise, for periodic republish (TTL refresh).
  final Map<String, _Provided> _provided = {};
  // Arbitrary DHT keys we advertise regardless of the file serve-quota (used for
  // folder discovery: folderId -> provider). Republished alongside files.
  final Map<String, _Provided> _providedKeys = {};

  /// The Kademlia index node (provider lookup/publish). Null unless [enableDht].
  DhtNode? dht;

  /// Kademlia bucket size / lookup breadth and per-round fan-out. Defaulted to
  /// cover a small overlay (see the constructor); exposed so the host can stage
  /// them down as the new-code fleet grows dense enough for replication.
  final int dhtK;
  final int dhtAlpha;

  /// Persistence anchors: always-on holder identities (e.g. relay indexers) the
  /// DHT additionally STOREs to and queries first. Supplied by the host so the
  /// library stays free of app concepts; null/empty → classic Kademlia.
  final Iterable<RnsIdentity> Function()? stableAnchors;

  /// What this node can say about a holder when it answers "these devices have
  /// it": power, uplink and radios, so a caller can prefer the box on mains over
  /// somebody's phone on a metered plan. Supplied by the host, which owns the
  /// relay directory; null = we report freshness only, which is still the signal
  /// that matters most.
  HolderHint? Function(Uint8List providerPub)? holderHint;

  /// Serving-side budget / anti-abuse guard applied to everything we serve.
  final ServeQuota serveQuota;

  /// Legacy per-identity next-hop resolver (any of the identity's paths). Reticulum
  /// routes per-DESTINATION, so prefer [nextHopForDest]/[hasPathForDest] below;
  /// this stays only as a fallback.
  final Uint8List? Function(RnsIdentity peer)? nextHopFor;

  /// Per-destination next-hop transport (null = direct neighbour). Supplied by the
  /// host (RnsTransport.pathFor(destHash).nextHop). Routing is per-destination —
  /// the same node's files/dht/chat dests can be reached via different hubs — so
  /// the link request MUST be transport-addressed to the hub that has a route to
  /// THIS specific destination, or the intermediate hub drops it.
  final Uint8List? Function(Uint8List destHash)? nextHopForDest;

  /// Whether the host has a path to [destHash] (RnsTransport.hasPath).
  final bool Function(Uint8List destHash)? hasPathForDest;

  /// Hardware MTU of the interface a packet to [destHash] would leave on
  /// (RnsTransport.nextHopInterfaceHwMtu). Lets an outbound link offer a larger
  /// link MTU over TCP (link MTU discovery). Null → no discovery (500).
  final int Function(Uint8List destHash)? nextHopMtuForDest;

  /// Called when we OPEN an outbound link to [destHash] (linkId, destHash), so
  /// the host can pin the link's interface to that dest's path up front (the LAN)
  /// — before the responder's proof, which arrives on every interface, can
  /// mis-set it to a slow hub. Optional.
  final void Function(Uint8List linkId, Uint8List destHash)? onLinkOpened;

  /// Pull a transport path to [destHash] (a PATH_REQUEST). Supplied by the host
  /// (RnsTransport.requestPath). Needed because we often know a peer's IDENTITY
  /// (e.g. a DHT contact learned from an incoming STORE) without having a cached
  /// path to it — its announce was never passively flooded to us on busy/
  /// asymmetric public hubs. A path request is a PULL the peer's attached hub
  /// answers on our direct link, so the DHT/file links below become routable.
  final void Function(Uint8List destHash)? requestPath;

  /// Called when we serve a file's manifest to another node (one download by a
  /// peer), with the 32-byte file hash and the requester key (the link id).
  /// Drives the per-file download metric and per-folder unique-leecher count.
  final void Function(Uint8List fileHash, String requesterId)? onServed;

  /// Store-and-forward hosting hooks (see FileServeSession). When both are set
  /// this node accepts blob deposits from peers; null = deposits declined.
  /// [linkIdHex] is the link the offer arrived on: an Archiver treats the LINK
  /// as policy, because a peer that reached it over the LAN, Bluetooth or LoRa
  /// has no route to anywhere else, and that data dies if it is refused.
  final DepositVerdict Function(Uint8List sha, int size, String ext,
      String pubHex, String sigHex, String linkIdHex)? onDepositOffer;
  final void Function(
      Uint8List sha, Uint8List bytes, String originPubHex, int tier, String ext)?
      onDepositStore;

  FileTransferNode({
    required this.identity,
    required this.source,
    required this.send,
    this.log,
    bool enableDht = false,
    ServeQuota? serveQuota,
    this.nextHopFor,
    this.nextHopForDest,
    this.hasPathForDest,
    this.requestPath,
    this.onLinkOpened,
    this.nextHopMtuForDest,
    this.onServed,
    this.onDepositOffer,
    this.onDepositStore,
    this.rpcApp = kDhtApp,
    this.rpcAspects = kDhtAspects,
    this.onRelayFrame,
    this.dhtK = 96,
    this.dhtAlpha = 12,
    this.stableAnchors,
    this.partialStore,
  }) : serveQuota = serveQuota ?? ServeQuota() {
    if (enableDht) {
      // k is sized to COVER the whole (small, tens-of-nodes) overlay, not the
      // Kademlia default of 8. `closest(target, k)` returns min(k, overlay size),
      // so k=96 simply means "query every peer we know"; it is not wasteful on a
      // 37-node overlay (it queries 37). This matters because, mid-migration,
      // chat-routed replication only lands on the NEW-code nodes (the rest still
      // run DHT on xprs/dht), so redundancy among the closest is sparse and a
      // resolver MUST be able to reach the holder itself — which it can only
      // guarantee by covering the overlay. This 96 is the SAFE default for a
      // consumer WITHOUT persistence anchors. A consumer that supplies anchors
      // (DhtNode.anchors / stableAnchors) can lower k well below the overlay size
      // — findability no longer depends on covering it, since resolve queries the
      // anchors first regardless of distance/k (Aurora runs k=20/alpha=6). k/alpha
      // are constructor params so staging needs no library edit. Liveness eviction
      // (routing_table.dart) also trims the cost: dead/unreachable contacts drop, so the
      // covered set shrinks to live nodes. alpha is the per-round fan-out.
      dht = DhtNode(
          identity: identity,
          k: dhtK,
          alpha: dhtAlpha,
          sendRpc: _dhtSendRpc,
          log: log,
          // Persistence anchors: adapt the host-supplied always-on identities to
          // DhtContacts. publish() also stores to them and resolve() queries them
          // first, so records survive churn and stay findable independent of k.
          anchors: stableAnchors == null
              ? null
              : () => [
                    for (final id in stableAnchors!())
                      DhtContact.ofIdentity(id)
                  ])
        // What we can honestly say about each holder we hand out. The DHT knows
        // freshness; only the host knows the hardware (it owns the relay
        // directory), so it fills the rest in.
        ..hintProvider = holderHint;
    }
  }

  /// Resolve the next hop to [peer]'s (app, aspects) destination, pulling a path
  /// first if we don't have one. We may know the peer's identity (a DHT contact)
  /// without a cached path because its announce was never flooded to us on busy
  /// hubs; a PATH_REQUEST is answered by the hub the peer is attached to. Mirrors
  /// LxmfRouter's request-then-wait. Returns the hop (may still be null).
  Future<Uint8List?> _ensurePath(
          RnsIdentity peer, String app, List<String> aspects) =>
      RnsLink.ensurePath(peer, app, aspects,
          nextHopFor: nextHopFor,
          nextHopForDest: nextHopForDest,
          hasPathForDest: hasPathForDest,
          requestPath: requestPath,
          // A path PULL to a provider we resolved via the DHT (whose announce we
          // never heard) must cross to the hub it's attached to and back. 3s is
          // too short on busy/asymmetric public hubs and makes the file link open
          // unroutable (broadcast) → handshake timeout. Give it ~9s before
          // falling back, well within the 12s provider-ready window.
          maxPolls: 30);

  /// Learn a peer (from its announce) as a DHT contact.
  void addPeerFromAnnounce(RnsIdentity peer) =>
      dht?.routing.add(DhtContact.ofIdentity(peer));

  /// Warm-start the DHT overlay from a cache of known peer public keys (64-byte
  /// RNS public keys, e.g. from a persisted observed-node store). Seeds the
  /// routing table so resolve/publish can act immediately on boot instead of
  /// waiting for live announces to re-populate it. Returns how many were added.
  int seedPeers(Iterable<Uint8List> publicKeys) {
    final d = dht;
    if (d == null) return 0;
    var n = 0;
    for (final pub in publicKeys) {
      if (pub.length != 64) continue;
      try {
        d.routing.add(DhtContact.fromPublicKey(pub));
        n++;
      } catch (_) {/* skip a malformed key */}
    }
    return n;
  }

  /// Pull transport paths to [peer]'s DHT and files destinations (a cheap
  /// PATH_REQUEST per dest, which the peer's attached hub answers on our direct
  /// link) so the first resolve/fetch to it is routable WITHOUT waiting for a
  /// live announce to be flooded to us. Used by warm-start against cached peers.
  void requestPeerPaths(RnsIdentity peer) {
    final rp = requestPath;
    if (rp == null) return;
    rp(RnsDestination.hash(peer, rpcApp, rpcAspects)); // the DHT RPC dest (chat)
    rp(RnsDestination.hash(peer, kFilesApp, kFilesAspects));
  }

  /// Number of confirmed Aurora DHT peers in the routing table (overlay
  /// membership). 0 means we've heard no other node's xprs/dht announce, so
  /// publish/resolve can only act locally — useful for diagnosing discovery.
  int get dhtRoutingSize => dht?.routing.size ?? 0;

  /// DHT keys we custody (our own + replicas from peers), and — the signal that
  /// replication is landing — how many of those records came from OTHER nodes.
  int get dhtStoredKeys => dht?.storedKeys ?? 0;
  int get dhtReplicasStored => dht?.replicasStored ?? 0;
  int get dhtProvidersDemoted => dht?.providersDemoted ?? 0;
  int get dhtStoresRejected => dht?.storesRejected ?? 0;

  /// Identity hashes of the DHT peers in the routing table (debug: lets us see
  /// WHICH Aurora nodes are in the overlay, to diagnose discovery convergence).
  List<String> get dhtPeerHexes =>
      dht?.routing.contacts.map((c) => c.identity.hexHash).toList() ??
      const <String>[];

  /// Feed an inbound packet. Returns true if it was a file/link packet we
  /// consumed (so the caller can skip announce handling). Safe to call for every
  /// packet.
  Future<bool> handlePacket(RnsPacket p, {int arrivalHwMtu = kRnsMtu}) async {
    // 1) A peer opening a link to one of our destinations.
    if (p.packetType == RnsPacketType.linkRequest) {
      if (RnsCrypto.constantTimeEquals(p.destHash, filesDestHash)) {
        await _acceptLink(p, arrivalHwMtu);
        return true;
      }
      // Accept DHT links on the configured RPC dest (the chat dest in Aurora; the
      // xprs/dht dest by default). The files dest is matched first above and
      // the dests are disjoint, so a real file link is never mis-accepted as DHT.
      if (dht != null &&
          RnsCrypto.constantTimeEquals(p.destHash, rpcDestHash)) {
        await _acceptDhtLink(p, arrivalHwMtu);
        return true;
      }
    }
    // 2) Traffic on an existing link (handshake proof, link data, resource).
    if (p.destType == RnsDestType.link) {
      final id = _hex(p.destHash);
      final serve = _serve[id];
      if (serve != null) {
        _onServePacket(serve, p);
        return true;
      }
      final fetch = _fetch[id];
      if (fetch != null) {
        await _onFetchPacket(fetch, p);
        return true;
      }
      final piece = _pieces[id];
      if (piece != null) {
        _onPiecePacket(piece, p);
        return true;
      }
      final dep = _deposit[id];
      if (dep != null) {
        await _onDepositPacket(dep, p);
        return true;
      }
      final ds = _dhtServeLinks[id];
      if (ds != null) {
        await _onDhtServePacket(ds, p);
        return true;
      }
      final dr = _dhtRpcByLink[id];
      if (dr != null) {
        await _onDhtRpcPacket(dr, p);
        return true;
      }
    }
    return false;
  }

  // ── Serve side ─────────────────────────────────────────────────────────
  Future<void> _acceptLink(RnsPacket request, int arrivalHwMtu) async {
    // A repeated LINKREQUEST (retransmit, or one copy per interface) must not
    // mint a second responder link: the link id is a hash of the request and so
    // repeats, while the ephemeral keypair does not — re-keying it makes every
    // later packet from the initiator fail its HMAC. Replay the proof instead.
    // The DHT serve path below already does this; this one did not.
    final known = _serve[_hex(RnsLink.linkIdFromRequest(request))];
    if (known != null) {
      final cached = known.proof;
      if (cached != null) send(cached);
      return;
    }
    try {
      final link =
          await RnsLink.responder(identity, request, arrivalHwMtu: arrivalHwMtu);
      final id = _hex(link.linkId!);
      log?.call('files: accepted link $id mtu=${link.mtu} '
          '(arrivalHwMtu=$arrivalHwMtu)');
      final entry = _ServeEntry(
        link,
        FileServeSession(link, source,
            quota: serveQuota,
            requesterId: id,
            onServed: onServed,
            onDepositOffer: onDepositOffer,
            onDepositStore: onDepositStore,
            log: log),
      );
      _serve[id] = entry;
      final proof = (await link.buildProof()).pack();
      entry.proof = proof;
      send(proof);
    } catch (e) {
      log?.call('files: accept link failed: $e');
    }
  }

  void _onServePacket(_ServeEntry e, RnsPacket p) {
    if (e.link.status != RnsLinkStatus.active &&
        p.context == RnsContext.lrrtt) {
      e.link.handleRtt(p); // activate
      return;
    }
    final outs = e.serve.onPacket(p);
    for (final out in outs) {
      send(out.pack());
    }
  }

  // ── Fetch side ─────────────────────────────────────────────────────────
  /// Fetch [fileHash] (sha256, 32B) from [providerPublicIdentity] (learned from
  /// an announce). Returns the verified bytes, or null on failure/timeout.
  Future<Uint8List?> fetch(
    Uint8List fileHash,
    RnsIdentity providerPublicIdentity, {
    Duration timeout = const Duration(minutes: 20),
  }) {
    // Coalesce concurrent fetches of the SAME content-addressed file so callers
    // can't race the same partial / open competing links. Any provider yields the
    // same verified bytes.
    final key = _hex(fileHash);
    final existing = _inflightBySha[key];
    if (existing != null) return existing;
    // NOTE: the cleanup MUST be a statement body, not `() => _inflightBySha
    // .remove(key)`. Map.remove returns the removed value — which here IS this
    // very whenComplete future — and an arrow makes the callback RETURN it, so
    // whenComplete awaits its own result: a circular deadlock. The future then
    // never completes even though the fetch finished, and the caller hangs
    // forever. A block body returns void and breaks the cycle.
    final fut = _fetchWithRetries(fileHash, providerPublicIdentity, timeout)
        .whenComplete(() {
      _inflightBySha.remove(key);
    });
    _inflightBySha[key] = fut;
    return fut;
  }

  Future<Uint8List?> _fetchWithRetries(
    Uint8List fileHash,
    RnsIdentity providerPublicIdentity,
    Duration timeout,
  ) async {
    // The link handshake (request -> proof -> RTT) can be lost over a lossy,
    // high-RTT cross-network path: the responder's LRPROOF in particular is sent
    // on all interfaces and a copy can be dropped before it returns. Re-sending
    // the SAME request is useless (RNS dedups by packet hash), so each retry
    // builds a FRESH link (new ephemeral key -> new link id -> new packet).
    // Once the handshake completes the transfer phase is single-interface and
    // reliable, so we only retry the handshake itself.
    const handshakeAttempts = 6;
    for (var attempt = 0; attempt < handshakeAttempts; attempt++) {
      final (result, handshakeOk) =
          await _fetchOnce(fileHash, providerPublicIdentity, timeout);
      // Got the bytes, or the handshake established and the transfer ran (and
      // failed for a real reason) — either way don't re-handshake.
      if (result != null || handshakeOk) return result;
      log?.call('files: handshake attempt ${attempt + 1} failed, retrying '
          '${_hex(fileHash)}');
    }
    return null;
  }

  /// One link-open + handshake + transfer attempt. Returns (bytesOrNull,
  /// handshakeCompleted) so [fetch] can decide whether to re-handshake.
  Future<(Uint8List?, bool)> _fetchOnce(
    Uint8List fileHash,
    RnsIdentity providerPublicIdentity,
    Duration timeout,
  ) async {
    final link =
        await RnsLink.initiator(providerPublicIdentity, kFilesApp, kFilesAspects);
    link.nextHop =
        await _ensurePath(providerPublicIdentity, kFilesApp, kFilesAspects);
    // Link MTU discovery: offer the next-hop interface's MTU so a TCP path
    // negotiates large resource parts (falls back to 500 with no callback).
    link.offerMtu(nextHopMtuForDest?.call(link.destHash) ?? kRnsMtu);
    log?.call('files: link offer mtu=${link.mtu} for ${_hex(link.destHash)}');
    final req = link.buildRequest();
    final entry = _FetchEntry(link, fileHash, Completer<Uint8List?>());
    entry.baseTimeout = timeout;
    final id = _hex(link.linkId!);
    _fetch[id] = entry;
    // Pin this link to the SAME interface its dest's path uses (the LAN), before
    // any packet flows. The responder answers the request on every interface (it
    // has no link-iface record yet), so our proof can arrive over a slow hub
    // copy and mis-set the link's interface — sending our GET_FILE there, where
    // it's lost. Pinning up front keeps all our link DATA on the fast path.
    onLinkOpened?.call(link.linkId!, link.destHash);
    const tick = Duration(seconds: 4);
    // Per-attempt handshake budget (~32s); [fetch] retries with a fresh link.
    const maxHandshakeStalls = 8;
    // Once bytes are flowing, tolerate long no-progress gaps: over a lossy,
    // high-RTT cross-network path a healthy large transfer can go minutes
    // between visible byte advances (slow segment transitions, HMU round-trips,
    // a Wi-Fi blip). Reference RNS scales its part timeout by the link's
    // measured throughput; we approximate that with a generous fixed budget
    // (~5 min of dead air) and re-request every tick to drive recovery.
    const maxTransferStalls = 75;
    var lastSeen = -1;
    var stalls = 0;
    var probeTicks = 0;
    entry.retry = Timer.periodic(tick, (_) {
      final f = entry.fetch;
      if (f == null) {
        if (++stalls > maxHandshakeStalls && !entry.done.isCompleted) {
          entry.done.complete(null); // handshake never completed -> retry
        }
        return;
      }
      // Resume probe: a provider that predates GET_FILE_FROM never advertises a
      // segment for our resume request. After ~8s of silence, fall back to a full
      // fetch on the same (still-active) link instead of stalling for minutes.
      if (entry.resumeUsed && !entry.restartedFull && f.totalBytes == 0) {
        if (++probeTicks >= 2) {
          log?.call('files: resume not answered, full fetch ${_hex(fileHash)}');
          // ignore: discarded_futures
          _restartFull(entry);
          return;
        }
      }
      final got = f.receivedBytes;
      if (got != lastSeen) {
        lastSeen = got; // progress (any rate) — keep going
        stalls = 0;
        return;
      }
      // No byte progress this tick — log the receiver state to diagnose stalls.
      log?.call('fetch stall tick ${stalls + 1}: ${f.debugState}');
      if (++stalls > maxTransferStalls) {
        if (!entry.done.isCompleted) {
          log?.call('files: fetch stalled ($maxTransferStalls dead ticks) '
              '${_hex(fileHash)}');
          entry.done.complete(null);
        }
        return;
      }
      // Re-request the still-missing parts (retry() also shrinks the window).
      for (final out in f.retry()) {
        send(out.pack());
      }
    });
    send(req.pack());
    final result = await entry.done.future;
    entry.timeout?.cancel();
    entry.retry?.cancel();
    _fetch.remove(id);
    if (result != null && partialStore != null) {
      // Whole file in hand — drop any partial (after pending segment writes flush).
      // ignore: discarded_futures
      entry.persist
          .then((_) => partialStore!.delete(fileHash))
          .catchError((Object err) {
        log?.call('files: partial delete failed: $err');
      });
    }
    return (result, entry.fetch != null);
  }

  Future<void> _onFetchPacket(_FetchEntry e, RnsPacket p) async {
    // Handshake: validate the responder's proof, send LRRTT, start the fetch.
    if (e.fetch == null) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        // The link request is emitted on ALL interfaces (an asymmetric LAN may
        // be one-way, so we can't pin it), so the responder can answer on more
        // than one and we receive a DUPLICATE proof. The first completes the
        // handshake (status leaves `pending`) and kicks off _startSession
        // asynchronously; a duplicate arriving in that gap (e.fetch still null)
        // would hit handleProof again, get null because the link is no longer
        // pending, and — before this guard — call _finishFetch(null), killing
        // the just-established session. Only a genuine failure of a STILL-pending
        // link is a real validation failure; ignore duplicates.
        if (e.link.status != RnsLinkStatus.pending) return;
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          _finishFetch(e, null, 'proof validation failed');
          return;
        }
        e.rttRaw = rtt.pack();
        send(e.rttRaw!);
        await _startSession(e); // loads any partial → GET_FILE_FROM, else GET_FILE
      }
      return;
    }
    // A duplicate LRPROOF after our link is already active means the responder
    // never received our LRRTT (it can be lost / arrive on an interface the
    // responder didn't pin its link to), so it keeps re-proofing and never
    // starts serving — the transfer stalls with recv=0. Re-send the RTT so the
    // responder's half of the link completes and it begins serving.
    // CRITICAL: only while the transfer has NOT started (receivedBytes == 0).
    // Once data is flowing the link is proven both-ways; continuing to re-send
    // the RTT makes the responder re-proof, and since _fetch[id] isn't cleared
    // until the fetch's completion microtask runs, that microtask gets starved
    // by an endless RTT↔proof ping-pong — the transfer completes but the fetch
    // future never resolves.
    if (p.packetType == RnsPacketType.proof &&
        p.context == RnsContext.lrproof) {
      if (e.rttRaw != null && (e.fetch?.receivedBytes ?? 0) == 0) {
        send(e.rttRaw!);
      }
      return;
    }
    // Active: drive the fetch session.
    final f = e.fetch!;
    for (final out in f.onPacket(p)) {
      send(out.pack());
    }
    final got = f.receivedBytes;
    if (got > 0) {
      _fetchProgress[_hex(e.fileHash)] = (received: got, total: f.totalBytes);
    }
    if (f.state == FileFetchState.done) {
      _finishFetch(e, f.result, null);
    } else if (f.state == FileFetchState.failed) {
      // A resumed transfer rejected (unsupported / different file) or that failed
      // the final sha → discard the partial and retry from segment 0 on this same
      // link rather than abandoning the file.
      if (e.resumeUsed && !e.restartedFull) {
        await _restartFull(e);
        return;
      }
      _finishFetch(e, null, f.error);
    }
  }

  /// Build the fetch session once the link is active: load any persisted partial
  /// and resume from it (GET_FILE_FROM), else fetch the whole file (GET_FILE).
  Future<void> _startSession(_FetchEntry e) async {
    ResumeState? resume;
    final store = partialStore;
    if (store != null) {
      try {
        resume = await store.load(e.fileHash);
      } catch (err) {
        log?.call('files: partial load failed: $err');
      }
    }
    if (e.done.isCompleted) return; // a probe/timeout may have fired meanwhile
    e.resumeUsed = resume != null;
    final f = FileFetchSession(e.link, e.fileHash,
        resume: resume, onSegment: _segmentPersister(e));
    e.fetch = f;
    send(f.start().pack());
  }

  /// Restart this fetch as a full (segment-0) transfer on the same active link —
  /// after a resume was rejected or went unanswered. Drops the unusable partial.
  Future<void> _restartFull(_FetchEntry e) async {
    e.restartedFull = true;
    e.resumeUsed = false;
    final store = partialStore;
    if (store != null) {
      try {
        await store.delete(e.fileHash);
      } catch (_) {}
    }
    if (e.done.isCompleted) return;
    final f =
        FileFetchSession(e.link, e.fileHash, onSegment: _segmentPersister(e));
    e.fetch = f;
    send(f.start().pack());
  }

  /// A per-fetch callback that serially persists each completed non-final segment
  /// to the partial store (in completion order); null when no store is configured.
  void Function(int, Uint8List)? _segmentPersister(_FetchEntry e) {
    final store = partialStore;
    if (store == null) return null;
    return (idx, seg) {
      final total = e.fetch?.totalBytes ?? 0;
      e.persist = e.persist
          .then((_) => store.appendSegment(e.fileHash, idx, seg, total: total))
          .catchError((Object err) {
        log?.call('files: partial append failed: $err');
      });
    };
  }

  void _finishFetch(_FetchEntry e, Uint8List? result, String? err) {
    if (err != null) log?.call('files: fetch failed: $err');
    _fetchProgress.remove(_hex(e.fileHash));
    if (!e.done.isCompleted) e.done.complete(result);
  }

  // ── Deposit side (ask a host to keep a blob) ───────────────────────────────
  final Map<String, _DepositEntry> _deposit = {}; // link_id hex -> deposit

  /// Deposit [bytes] (sha256 = [sha], extension [ext]) to [hostPublicIdentity]
  /// for store-and-forward hosting. [pub]/[sig] are the depositor's NOSTR x-only
  /// pubkey (32B) and a Schnorr signature over depositAuthMessageHex(shaHex) (64B)
  /// that authorizes hosting this blob. Returns true if the host stored it.
  Future<bool> deposit(
    Uint8List sha,
    Uint8List bytes,
    String ext,
    Uint8List pub,
    Uint8List sig,
    RnsIdentity hostPublicIdentity, {
    Duration timeout = const Duration(seconds: 60),
  }) async {
    final link =
        await RnsLink.initiator(hostPublicIdentity, kFilesApp, kFilesAspects);
    link.nextHop =
        await _ensurePath(hostPublicIdentity, kFilesApp, kFilesAspects);
    final req = link.buildRequest();
    final entry = _DepositEntry(link, sha, bytes, ext, pub, sig, Completer<bool>());
    final id = _hex(link.linkId!);
    _deposit[id] = entry;
    entry.timeout = Timer(timeout, () {
      if (!entry.done.isCompleted) {
        log?.call('files: deposit timeout ${_hex(sha)}');
        entry.done.complete(false);
      }
    });
    send(req.pack());
    final ok = await entry.done.future;
    entry.timeout?.cancel();
    _deposit.remove(id);
    return ok;
  }

  Future<void> _onDepositPacket(_DepositEntry e, RnsPacket p) async {
    if (e.dep == null) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(false);
          return;
        }
        send(rtt.pack());
        final d =
            FileDepositSession(e.link, e.sha, e.bytes, e.ext, e.pub, e.sig);
        e.dep = d;
        send(d.start().pack());
      }
      return;
    }
    final d = e.dep!;
    for (final out in d.onPacket(p)) {
      send(out.pack());
    }
    if (d.state == FileDepositState.done) {
      if (!e.done.isCompleted) e.done.complete(true);
    } else if (d.state == FileDepositState.failed) {
      log?.call('files: deposit rejected: ${d.error}');
      if (!e.done.isCompleted) e.done.complete(false);
    }
  }

  // ── DHT over Reticulum links ───────────────────────────────────────────────
  /// Resolve providers for [sha256] via the DHT, then fetch the file from
  /// several of them in parallel (multi-source). Returns the verified bytes.
  /// Live download progress (received, total bytes) for an in-flight
  /// content-addressed fetch of [sha256], or null when nothing is downloading.
  ({int received, int total})? fetchProgress(Uint8List sha256) =>
      _fetchProgress[_hex(sha256)];

  /// Resolve providers for [sha256] via the DHT and fetch the whole file from the
  /// best available one over a single RNS Resource (the Resource layer segments,
  /// windows and HMUs it for arbitrary size). Falls back to the next provider on
  /// failure. Returns the sha-verified bytes, or null.
  Future<Uint8List?> resolveAndFetch(
    Uint8List sha256, {
    Duration timeout = const Duration(minutes: 20),
  }) async {
    final d = dht;
    if (d == null) return null;
    final providers = await d.resolve(sha256);
    log?.call('files: resolved ${providers.length} provider(s) for '
        '${_hex(sha256).substring(0, 8)}');
    final self = _hex(identity.hash);
    for (final pr in providers) {
      if (_hex(pr.providerIdentity.hash) == self) continue;
      final bytes = await fetch(sha256, pr.providerIdentity, timeout: timeout);
      if (bytes != null && bytes.isNotEmpty) return bytes;
      // Provider failed to serve the bytes → prune its record from our local DHT
      // store so the next resolve (here, or by a peer that queries us) doesn't
      // waste a round on a dead holder. It re-publishes (~30 min) to return.
      d.demoteProvider(sha256, pr.providerPub);
    }
    return null;
  }

  /// Announce ourselves as a provider of [sha256] (auto-seed): publish a signed
  /// provider record at the k DHT nodes closest to the file key, and remember it
  /// for periodic republish. Returns how many holders accepted it.
  Future<int> publishProvider(
    Uint8List sha256, {
    int capacity = kCapUnknown,
    Uint8List? manifestHash,
  }) async {
    _provided[_hex(sha256)] =
        _Provided(Uint8List.fromList(sha256), capacity, manifestHash);
    return _publishOne(sha256, capacity, manifestHash);
  }

  // ── The piece engine (aurora/docs/torrents.md §8 step 2) ──────────────────
  //
  // Fetch ONE file from MANY peers at once, in pieces, verifying each piece
  // against a hash the folder's owner signed. Three properties make this a swarm
  // rather than a download queue, and all three are load-bearing:
  //
  //   * every piece is verifiable ON ITS OWN, so bytes from a stranger are safe
  //     to use — the liar is caught on the piece, not after the last byte of a
  //     4 GB file;
  //   * a PARTIAL holder is a source (GET_HAVE returns its bitfield), so a peer
  //     that is 40% done uploads those 40% and a 50-peer swarm has 50 uploaders
  //     instead of one;
  //   * the tail is not held hostage: in the endgame the last few pieces are
  //     asked of every idle peer at once and the first answer wins.
  //
  // Rarest-first, because the piece only one peer holds is the one that
  // disappears when that peer does.

  /// Progress of a piece fetch, for a UI that wants to say something true.
  final Map<String, ({int have, int total})> _pieceProgress = {};
  ({int have, int total})? pieceProgressFor(Uint8List fileHash) =>
      _pieceProgress[_hex(fileHash)];

  /// Fetch [fileHash] from a swarm, in pieces, verifying each against
  /// [pieceHashes] (index i = sha256 of piece i — SIGNED by the folder owner, so
  /// a stranger's bytes are checkable before they are trusted).
  ///
  /// Returns the assembled file, or null when the swarm could not produce every
  /// piece. Falls back to nothing: the caller decides whether to try a plain
  /// whole-file fetch (which is what a provider that predates this speaks).
  Future<Uint8List?> fetchFilePieces({
    required Uint8List fileHash,
    required int size,
    required int pieceSize,
    required List<Uint8List> pieceHashes,
    required List<RnsIdentity> providers,
    int maxPeers = 4,
    Duration timeout = const Duration(minutes: 20),
  }) async {
    final count = pieceCountFor(size, pieceSize);
    if (count == 0 || pieceHashes.length != count || providers.isEmpty) {
      return null;
    }
    final key = _hex(fileHash);
    final out = Uint8List(size);
    final done = List<bool>.filled(count, false);
    var haveCount = 0;
    _pieceProgress[key] = (have: 0, total: count);

    // Open up to maxPeers links, in parallel. A peer that never completes its
    // handshake, or holds nothing, simply isn't in the swarm.
    final peers = <_PieceEntry>[];
    await Future.wait([
      for (final p in providers.take(maxPeers))
        _openPiecePeer(p, fileHash, pieceSize).then((e) {
          if (e != null) peers.add(e);
        }).catchError((Object err) {
          // A peer that cannot be opened is not a swarm failure — but swallowing
          // WHY is how a swarm that never forms looks like a swarm with nothing
          // in it.
          log?.call('files: piece peer failed: $err');
        }),
    ]);
    if (peers.isEmpty) {
      log?.call('files: no piece peers answered for ${key.substring(0, 8)}');
      _pieceProgress.remove(key);
      return null;
    }
    log?.call('files: piece swarm for ${key.substring(0, 8)}: '
        '${peers.length} peer(s), $count piece(s) of $pieceSize B');

    final deadline = DateTime.now().add(timeout);
    final inFlight = <int, Set<_PieceEntry>>{}; // piece -> peers asked

    try {
      while (haveCount < count && DateTime.now().isBefore(deadline)) {
        final live = peers.where((p) => !p.dead && p.pending == null).toList();
        if (live.isEmpty) {
          if (peers.every((p) => p.dead)) break; // swarm is gone
          await Future<void>.delayed(const Duration(milliseconds: 50));
          continue;
        }

        // What is left, rarest first: the piece the fewest peers hold is the one
        // that vanishes when its only holder does.
        final want = <int>[];
        for (var i = 0; i < count; i++) {
          if (!done[i]) want.add(i);
        }
        want.sort((a, b) => _holdersOf(peers, a).compareTo(_holdersOf(peers, b)));

        // Endgame: with only a few pieces left, ask EVERY idle peer for them and
        // take the first answer. Otherwise one slow peer owns the last 2%.
        final endgame = want.length <= live.length;

        var assigned = 0;
        for (final piece in want) {
          if (assigned >= live.length) break;
          final asked = inFlight.putIfAbsent(piece, () => <_PieceEntry>{});
          for (final peer in live) {
            if (peer.pending != null) continue;
            if (!(peer.session.mask?.has(piece) ?? false)) continue;
            if (asked.contains(peer)) continue;
            if (!endgame && asked.isNotEmpty) break; // one peer per piece
            asked.add(peer);
            assigned++;
            // ignore: discarded_futures
            _requestPiece(peer, piece, pieceSize, size).then((bytes) {
              if (bytes == null) return;
              if (done[piece]) return; // an endgame duplicate lost the race
              final h =
                  Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
              if (!RnsCrypto.constantTimeEquals(h, pieceHashes[piece])) {
                // The signed hash says these bytes are not the piece. Drop the
                // peer: a source that hands us garbage once will do it again,
                // and every other piece it gave us is now suspect only in the
                // sense that it was also checked — so we keep those and stop
                // asking this one.
                log?.call('files: piece $piece failed its signed hash — '
                    'dropping that peer');
                peer.dead = true;
                _closePiecePeer(peer);
                return;
              }
              out.setRange(piece * pieceSize,
                  piece * pieceSize + bytes.length, bytes);
              done[piece] = true;
              haveCount++;
              peer.served++;
              _pieceProgress[key] = (have: haveCount, total: count);
            }).whenComplete(() {
              asked.remove(peer);
            });
            if (!endgame) break;
          }
        }
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
    } finally {
      for (final p in peers) {
        _closePiecePeer(p);
      }
      _pieceProgress.remove(key);
    }

    if (haveCount < count) {
      log?.call('files: piece fetch incomplete ($haveCount/$count)');
      return null;
    }
    // The whole file must still hash to what was asked for. Every piece was
    // verified, so this can only fail if the piece-hash LIST itself was wrong —
    // which is worth knowing loudly rather than quietly returning bad bytes.
    final h = Uint8List.fromList(crypto.sha256.convert(out).bytes);
    if (!RnsCrypto.constantTimeEquals(h, fileHash)) {
      log?.call('files: pieces all verified but the file hash does not match — '
          'the piece-hash list is wrong');
      return null;
    }
    return out;
  }

  int _holdersOf(List<_PieceEntry> peers, int piece) {
    var n = 0;
    for (final p in peers) {
      if (!p.dead && (p.session.mask?.has(piece) ?? false)) n++;
    }
    return n;
  }

  /// Ask one peer for one piece. Completes with the bytes, or null.
  Future<Uint8List?> _requestPiece(
      _PieceEntry peer, int piece, int pieceSize, int size) async {
    if (peer.dead) return null;
    final offset = piece * pieceSize;
    final len = (offset + pieceSize > size) ? size - offset : pieceSize;
    final c = Completer<void>();
    peer.pending = c;
    peer.session.result = null;
    send(peer.session.askRange(offset, len).pack());
    try {
      await c.future.timeout(const Duration(seconds: 90));
    } on TimeoutException {
      // A peer that goes quiet on a piece is not a source right now. It is not
      // necessarily a liar, so it stays in the swarm — but this piece is re-issued.
      peer.pending = null;
      return null;
    }
    peer.pending = null;
    final bytes = peer.session.result;
    peer.session.result = null;
    return bytes;
  }

  /// Open a link to one provider and ask what it holds. Null when the handshake
  /// never completes or the peer holds nothing of this file.
  Future<_PieceEntry?> _openPiecePeer(
      RnsIdentity provider, Uint8List fileHash, int pieceSize) async {
    final link = await RnsLink.initiator(provider, kFilesApp, kFilesAspects);
    link.nextHop = await _ensurePath(provider, kFilesApp, kFilesAspects);
    link.offerMtu(nextHopMtuForDest?.call(link.destHash) ?? kRnsMtu);
    // The link id only exists once the request is BUILT — register after, or the
    // peer is routed to nothing and every packet from it is dropped.
    final req = link.buildRequest();
    final entry = _PieceEntry(link, PieceFetchSession(link, fileHash));
    final id = _hex(link.linkId!);
    _pieces[id] = entry;
    onLinkOpened?.call(link.linkId!, link.destHash);

    final ready = Completer<bool>();
    entry.ready = ready;
    send(req.pack());

    // Stall recovery while a range is in flight (re-request missing parts).
    entry.retry = Timer.periodic(const Duration(seconds: 4), (_) {
      if (entry.dead) return;
      if (entry.pending == null) return;
      for (final out in entry.session.retry()) {
        send(out.pack());
      }
    });

    try {
      final ok = await ready.future.timeout(const Duration(seconds: 30));
      if (!ok) {
        _closePiecePeer(entry);
        return null;
      }
    } on TimeoutException {
      _closePiecePeer(entry);
      return null;
    }

    // What does it have?
    final c = Completer<void>();
    entry.pending = c;
    send(entry.session.askHave(pieceSize).pack());
    try {
      await c.future.timeout(const Duration(seconds: 30));
    } on TimeoutException {
      _closePiecePeer(entry);
      return null;
    }
    entry.pending = null;
    final mask = entry.session.mask;
    if (mask == null || mask.isEmpty) {
      _closePiecePeer(entry);
      return null;
    }
    return entry;
  }

  void _onPiecePacket(_PieceEntry e, RnsPacket p) {
    if (e.dead) return;
    // Handshake, exactly as a whole-file fetch does it.
    if (e.ready != null && !e.ready!.isCompleted) {
      if (p.packetType == RnsPacketType.proof &&
          p.context == RnsContext.lrproof) {
        if (e.link.status != RnsLinkStatus.pending) return;
        // ignore: discarded_futures
        e.link.handleProof(p).then((rtt) {
          if (rtt == null) {
            if (!e.ready!.isCompleted) e.ready!.complete(false);
            return;
          }
          e.rttRaw = rtt.pack();
          send(e.rttRaw!);
          if (!e.ready!.isCompleted) e.ready!.complete(true);
        });
      }
      return;
    }
    // A responder that never saw our LRRTT keeps re-proofing; re-send it while
    // nothing is flowing yet (the same fix the whole-file path needed).
    if (p.packetType == RnsPacketType.proof &&
        p.context == RnsContext.lrproof) {
      if (e.rttRaw != null && e.session.receivedBytes == 0) send(e.rttRaw!);
      return;
    }
    for (final out in e.session.onPacket(p)) {
      send(out.pack());
    }
    final s = e.session.state;
    if (s == PieceReqState.done || s == PieceReqState.failed) {
      final c = e.pending;
      if (c != null && !c.isCompleted) c.complete();
    }
  }

  void _closePiecePeer(_PieceEntry e) {
    e.dead = true;
    e.retry?.cancel();
    final c = e.pending;
    if (c != null && !c.isCompleted) c.complete();
    final id = e.link.linkId;
    if (id != null) _pieces.remove(_hex(id));
  }

  /// Advertise ourselves as a provider of an arbitrary 32-byte DHT [key] (e.g. a
  /// folder id), independent of the file serve-quota — folders are metadata, not
  /// bulk bytes, so they should always be discoverable. Remembered for republish.
  Future<int> publishKey(Uint8List key, {int capacity = kCapUnknown}) async {
    final d = dht;
    if (d == null) return 0;
    _providedKeys[_hex(key)] = _Provided(Uint8List.fromList(key), capacity, null);
    final rec = await ProviderRecord.create(
        providerIdentity: identity, sha256: key, capacity: capacity);
    return d.publish(rec);
  }

  /// Resolve the provider node identities advertising a 32-byte [key] (folder id
  /// or sha256), best capacity first, excluding ourselves.
  Future<List<RnsIdentity>> resolveProviders(Uint8List key) async {
    final d = dht;
    if (d == null) return const [];
    final recs = await d.resolve(key);
    final self = _hex(identity.hash);
    return [
      for (final r in recs)
        if (_hex(r.providerIdentity.hash) != self) r.providerIdentity
    ];
  }

  /// Stop advertising [sha256] (let its record expire at TTL).
  void unpublishProvider(Uint8List sha256) => _provided.remove(_hex(sha256));

  int get providedCount => _provided.length;

  /// Re-publish all advertised files (refreshes TTL + re-stores at the current k
  /// closest nodes after churn). Drive from a periodic timer well under the TTL.
  Future<void> republishAll() async {
    for (final p in _provided.values.toList()) {
      await _publishOne(p.sha, p.capacity, p.manifestHash);
    }
    // Folder (and other ungated) keys advertise regardless of the serve-quota.
    final d = dht;
    if (d != null) {
      for (final p in _providedKeys.values.toList()) {
        final rec = await ProviderRecord.create(
            providerIdentity: identity, sha256: p.sha, capacity: p.capacity);
        await d.publish(rec);
      }
    }
    final n = _provided.length + _providedKeys.length;
    if (n > 0) log?.call('files: republished $n record(s)');
  }

  Future<int> _publishOne(Uint8List sha256, int capacity, Uint8List? manifestHash) async {
    final d = dht;
    if (d == null) return 0;
    // Don't advertise when we can't serve (off switch or daily budget spent) —
    // our records simply age out so resolvers route around us until we recover.
    if (!serveQuota.available) return 0;
    final rec = await ProviderRecord.create(
      providerIdentity: identity,
      sha256: sha256,
      capacity: capacity,
      manifestHash: manifestHash,
    );
    return d.publish(rec);
  }

  // DhtNode.sendRpc bridge: send a DHT message to a contact over a (transient)
  // link to its dht destination, await the single-packet reply.
  Future<DhtMessage?> _dhtSendRpc(DhtContact to, DhtMessage req) async {
    final reqBytes = req.encode();
    final rpcHash = RnsDestination.hash(to.identity, rpcApp, rpcAspects);
    // A STORE's ACK arrives a full extra round-trip after the data is already
    // stored, and publish fans out wide (contention), so its ACK routinely landed
    // just after the lookup-sized 6s wait — the publisher then logged the STORE
    // as failed even though the record had replicated. Give STOREs a longer ACK
    // budget; FINDs stay short (resolve early-exits, so it tolerates slow peers).
    final timeout = req.op == DhtOp.store
        ? const Duration(seconds: 12)
        : const Duration(seconds: 6);
    final respBytes =
        await _dhtRpcRaw(to.identity, reqBytes, rpcApp, rpcAspects, timeout: timeout);
    // Routing-table liveness (eviction). A reply proves the contact is alive. A
    // failure is only a DEATH signal when we actually had a route to try AND it
    // was a lookup: a no-route skip is about OUR paths (e.g. unwarmed at boot,
    // which would otherwise evict the whole table before paths converge), and a
    // missing STORE ack is frequently lost over multi-hop even when the record
    // landed — neither says the peer is dead. Only an unanswered FIND to a
    // routable peer counts toward eviction.
    final d = dht;
    if (d != null) {
      if (respBytes != null) {
        d.routing.recordSuccess(to);
      } else if (req.op != DhtOp.store &&
          (hasPathForDest?.call(rpcHash) ?? false)) {
        d.routing.recordFailure(to);
      }
    }
    return respBytes == null ? null : DhtMessage.decode(respBytes);
  }

  Future<Uint8List?> _dhtRpcRaw(RnsIdentity peer, Uint8List reqBytes, String app,
      List<String> aspects,
      {Duration timeout = const Duration(seconds: 6)}) async {
    // Resolve a route to the contact's RPC dest with a SHORT path wait. A DHT
    // lookup queries many contacts and tolerates individual misses, so we must
    // not spend the ~9s file-fetch path budget per contact. If there is no
    // route, skip this contact immediately instead of broadcasting a doomed
    // link request and waiting out the handshake — that 8s-per-stale-node cost,
    // times the whole shortlist, is what made resolve() take minutes.
    final destHash = RnsDestination.hash(peer, app, aspects);
    final hop = await RnsLink.ensurePath(peer, app, aspects,
        nextHopFor: nextHopFor,
        nextHopForDest: nextHopForDest,
        hasPathForDest: hasPathForDest,
        requestPath: requestPath,
        maxPolls: 10); // ~3s, vs 9s for a file fetch
    // No route resolved → skip. hop==null is AMBIGUOUS (it is also a direct
    // neighbour, HEADER_1), so gate on the path actually existing, not on hop —
    // otherwise we'd wrongly skip a directly-reachable (LAN) DHT contact.
    if (!(hasPathForDest?.call(destHash) ?? (hop != null))) return null;
    final link = await RnsLink.initiator(peer, app, aspects);
    link.nextHop = hop;
    // Offer the next-hop MTU so the link negotiates a larger size over TCP — lets
    // FIND replies carry more contacts/records per packet (sized in
    // _onDhtServePacket), fewer rounds. Falls back to 500 on BLE/old peers.
    link.offerMtu(nextHopMtuForDest?.call(destHash) ?? kRnsMtu);
    final reqPkt = link.buildRequest();
    final id = _hex(link.linkId!);
    final e = _DhtRpcEntry(link, reqBytes);
    _dhtRpcByLink[id] = e;
    send(reqPkt.pack());
    final resp = await e.done.future.timeout(timeout, onTimeout: () => null);
    _dhtRpcByLink.remove(id);
    return resp;
  }

  /// Answer a connectionless DHT probe (NPD) — no link, no handshake.
  ///
  /// Unlike the relay, a DHT FIND always HAS an answer (at minimum the closest
  /// contacts we know), so this normally replies. The win here is not silence,
  /// it is that the reply costs no asymmetric crypto: the pairwise NOSTR key is
  /// cached, so both the decrypt and the encrypt are symmetric-only, where a
  /// link handshake cost two Curve25519 mults plus a signature EVERY time.
  ///
  /// Replies are sized to fit one datagram; a peer that needs more opens a link.
  Future<({int type, Uint8List body})?> answerProbe(Uint8List body) async {
    final d = dht;
    if (d == null) return null;
    final inner = _untagDht(body);
    if (inner == null) return null;
    // Fit the answer inside one PLAIN packet: ~64 B per contact, ~185 B per
    // record (same accounting the link path uses, against a smaller budget).
    final budget = kNpdMaxPlaintext - 24;
    final maxC = (budget ~/ 64).clamp(1, kDhtWireMaxContacts);
    final maxR = (budget ~/ 185).clamp(1, kDhtWireMaxRecords);
    final resp =
        await d.handleEncoded(inner, maxContacts: maxC, maxRecords: maxR);
    if (resp == null) return null;
    final tagged = _tagDht(resp);
    if (tagged.length > kNpdMaxPlaintext) {
      // Too big for a datagram — tell the peer to come back over a link.
      return (type: NpdType.have, body: Uint8List(0));
    }
    return (type: NpdType.result, body: tagged);
  }

  Future<void> _acceptDhtLink(RnsPacket request, int arrivalHwMtu) async {
    // Dedup before the crypto — see the note in RelayNode._accept. The link-id
    // is a cheap hash; the handshake is two Curve25519 mults plus a signature.
    // A duplicate LINKREQUEST (same request, another interface) re-sends the
    // cached proof rather than signing a new one.
    final dupId = _hex(RnsLink.linkIdFromRequest(request));
    final cached = _dhtServeProofs[dupId];
    if (cached != null) {
      send(cached);
      return;
    }
    try {
      final link =
          await RnsLink.responder(identity, request, arrivalHwMtu: arrivalHwMtu);
      final id = _hex(link.linkId!);
      _dhtServeLinks[id] = link;
      _dhtServeOrder.add(id);
      if (_dhtServeOrder.length > _maxDhtServeLinks) {
        final evicted = _dhtServeOrder.removeAt(0);
        _dhtServeLinks.remove(evicted);
        _dhtServeProofs.remove(evicted);
      }
      final proof = (await link.buildProof()).pack();
      _dhtServeProofs[id] = proof;
      send(proof);
    } catch (e) {
      log?.call('dht: accept link failed: $e');
    }
  }

  Future<void> _onDhtServePacket(RnsLink link, RnsPacket p) async {
    if (link.status != RnsLinkStatus.active && p.context == RnsContext.lrrtt) {
      link.handleRtt(p);
      return;
    }
    if (p.context == RnsContext.none) {
      // The RPC dest is shared, so every link frame carries a 1-byte type tag:
      // 0x01 = DHT, 0x02 = relay. We handle DHT here and demux relay frames to
      // the relay tenant ([onRelayFrame]); anything else is ignored.
      final dec = link.decrypt(p);
      final relayBody = _untagRelay(dec);
      if (relayBody != null) {
        final resp = await onRelayFrame?.call(relayBody);
        if (resp != null) {
          send(link.encrypt(_tagRelay(resp), context: RnsContext.none).pack());
        }
        return;
      }
      final body = _untagDht(dec);
      if (body == null) return;
      // Size the FIND reply to the link's negotiated MTU: a large-MTU (TCP/chat)
      // link carries far more contacts/records in one packet than the 500-MTU
      // floor, cutting lookup rounds. ~162 B covers the msg header + token/packet
      // overhead + type tag; 64 B per contact, ~185 B per record.
      final budget = link.mtu - 162;
      final maxC = (budget ~/ 64).clamp(kDhtWireMaxContacts, 64);
      final maxR = (budget ~/ 185).clamp(kDhtWireMaxRecords, 16);
      final respBytes =
          await dht?.handleEncoded(body, maxContacts: maxC, maxRecords: maxR);
      if (respBytes != null) {
        send(link.encrypt(_tagDht(respBytes), context: RnsContext.none).pack());
      }
    }
  }

  Future<void> _onDhtRpcPacket(_DhtRpcEntry e, RnsPacket p) async {
    if (!e.sent) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(null);
          return;
        }
        send(rtt.pack());
        send(e.link.encrypt(_tagDht(e.reqBytes), context: RnsContext.none).pack());
        e.sent = true;
      }
      return;
    }
    if (p.context == RnsContext.none && !e.done.isCompleted) {
      e.done.complete(_untagDht(e.link.decrypt(p)));
    }
  }

  // Chat-dest link frames are type-tagged so DHT can share the destination with
  // future tenants: a DHT frame is [0x01, ...DhtMessage]. _untagDht returns the
  // body for a DHT-tagged frame, or null for anything else.
  static const int _kDhtFrame = 0x01;
  static Uint8List _tagDht(Uint8List body) =>
      Uint8List.fromList([_kDhtFrame, ...body]);
  static Uint8List? _untagDht(Uint8List frame) =>
      (frame.isNotEmpty && frame[0] == _kDhtFrame)
          ? Uint8List.sublistView(frame, 1)
          : null;

  // Relay tenant frames on the shared dest are tag 0x02 (== social
  // relay_node.dart kRelayRpcTag; kept as a literal to avoid a files->social
  // import). DHT is 0x01 above.
  static const int _kRelayFrame = 0x02;
  static Uint8List _tagRelay(Uint8List body) =>
      Uint8List.fromList([_kRelayFrame, ...body]);
  static Uint8List? _untagRelay(Uint8List frame) =>
      (frame.isNotEmpty && frame[0] == _kRelayFrame)
          ? Uint8List.sublistView(frame, 1)
          : null;

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}
