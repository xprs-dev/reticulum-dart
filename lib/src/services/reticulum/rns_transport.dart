/*
 * RNS transport: announce/path table + transport-node forwarding (RNS 1.3.5).
 *
 * Reticulum is NOT a DHT — destinations announce themselves and each node keeps,
 * per destination, the path it last heard the most recent announce on. A
 * TRANSPORT node also rebroadcasts inbound announces onto its other interfaces
 * so destinations on one segment become reachable from another (the bridging
 * that lets BLE / LoRa / LAN segments interconnect).
 *
 * Hop accounting (RNS/Transport.py): a received packet's hop count is +1'd on
 * arrival (the hop just taken). The path table stores that incremented value,
 * and a rebroadcast carries it on the wire as HEADER_2 with transport_type=
 * TRANSPORT and transport_id = this node's (relay) identity hash. The origin's
 * announce signature does not cover hops, so the original announce data is reused
 * verbatim.
 */
import 'dart:math';
import 'dart:typed_data';

import 'rns_announce.dart';
import 'rns_crypto.dart';
import 'rns_identity.dart';
import 'rns_link.dart';
import 'rns_packet.dart';

/// RNS PATHFINDER_M — maximum hops.
const int kRnsMaxHops = 128;

/// A transport interface: something that can send a raw RNS packet, with a
/// stable label so the transport can avoid echoing a packet back out the way it
/// came.
abstract class RnsInterface {
  String get label;
  void send(Uint8List packetRaw);

  /// True for discovery-only interfaces (e.g. the LAN UDP interface) that carry
  /// announces but DROP all data packets. A path learned on such an interface
  /// can never carry a link/DHT/file transfer, so it must not shadow a path
  /// learned on a data-capable interface (the hub). Default false.
  bool get announceOnly => false;

  /// Relative link speed for path preference among equally-capable paths:
  /// a co-located peer reachable over BOTH the LAN and an internet hub (or
  /// BLE) should be reached over the fastest medium. Higher = faster.
  /// 3 = LAN, 2 = TCP/UDP (default), 1 = BLE.
  int get speedRank => 2;

  /// The hardware MTU this interface can carry, used for link MTU discovery
  /// (RNS Interface.HW_MTU). The default [kRnsMtu] means "no discovery" — links
  /// over this interface stay at the 500-byte protocol MTU. Interfaces that can
  /// carry larger frames (TCP) override this to negotiate bigger resource parts.
  int get hardwareMtu => kRnsMtu;

  /// True for low-capacity EDGE interfaces (e.g. BLE) when this node is an
  /// [RnsTransport.edgeBridge]. The bridge propagates announces heard on an edge
  /// UP onto core interfaces, but never re-airs the core (internet) announce
  /// flood back onto an edge — that would saturate BLE and starve APRS. Default
  /// false.
  bool get edge => false;
}

/// Where we last heard an identity, and how confident we still are about it.
class _FastVia {
  _FastVia(this.label, this.heardMs);

  /// Interface label the identity was heard on.
  final String label;

  /// When we last heard the identity ON [label] — not merely when we last heard
  /// the identity at all, which is what makes this an expiry and not an LRU.
  int heardMs;

  /// Consecutive announces heard on a slower medium instead of [label].
  int misses = 0;
}

class RnsPathEntry {
  final Uint8List destHash;
  final RnsIdentity identity;
  final Uint8List publicKey;
  Uint8List appData;
  int hops; // RNS convention: received wire hops + 1
  String via; // interface label the announce arrived on
  // Next-hop transport id (16B) when the destination is reachable THROUGH a
  // transport node (the relayer's id from the HEADER_2 announce); null when the
  // destination is a direct neighbour. To send to a transported destination we
  // emit HEADER_2 with transport_type=TRANSPORT and transport_id=[nextHop] so the
  // transport forwards it.
  Uint8List? nextHop;
  int updatedMs;

  RnsPathEntry({
    required this.destHash,
    required this.identity,
    required this.publicKey,
    required this.appData,
    required this.hops,
    required this.via,
    required this.nextHop,
    required this.updatedMs,
  });
}

/// The narrow capability a connection-spawning interface (TCP server/gateway)
/// needs: registering each accepted connection as an interface. Implemented by
/// both the in-process [RnsTransport] and the isolate-hosted
/// RnsTransportClient, so servers work identically against either.
abstract class RnsInterfaceRegistry {
  void addInterface(RnsInterface iface);
  void removeInterface(RnsInterface iface);
}

class RnsTransport implements RnsInterfaceRegistry {
  final void Function(String msg)? log;

  /// When set, this node acts as a TRANSPORT node and rebroadcasts inbound
  /// announces onto its other interfaces, tagged with [transportId] (16-byte
  /// relay identity hash).
  Uint8List? transportId;

  /// Scoped "edge bridge" relaying (e.g. a phone bridging BLE peers onto the
  /// internet hubs). When true, [_rebroadcast] only propagates announces heard
  /// on an [RnsInterface.edge] interface, and only onto NON-edge (core)
  /// interfaces — so local BLE peers become reachable from the internet, but the
  /// internet announce flood is never re-aired back onto BLE (which would
  /// saturate it and starve APRS that shares the radio). Packet/link forwarding
  /// ([_maybeForward]) is unaffected and bridges both directions. When false
  /// (default) rebroadcast behaves like a normal transport node.
  bool edgeBridge = false;

  final List<RnsInterface> _interfaces = [];
  final Map<String, RnsPathEntry> _paths = {};

  /// LRU cap on the path table. A phone leaf attached to a full transport hub
  /// hears the entire network's announces; without a cap the table grows
  /// unbounded (the old out-of-memory). 2048 is far more than any one device
  /// talks to while keeping memory bounded.
  static const int _maxPaths = 2048;

  // Budget for verifying announces from *new* destinations, so a public hub's
  // network-wide flood can't build an endless crypto backlog on phone hardware.
  // Re-announces of known destinations are exempt (cheap, and keep active paths
  // fresh). Our own overlay's announces are priority-exempt below.
  static const int _annBudgetPerWindow = 1;
  static const int _annBudgetWindowMs = 3000;
  int _annWindowStart = 0;
  int _annCount = 0;
  // Global ceiling on REAL Ed25519 verifications per window, across every
  // announce class — including known-destination re-announces and priority
  // announces, which bypass the new-destination budget above. A re-announce
  // whose app_data changed (uptime fields churn every announce) misses the
  // trustIf fast-path and costs a full verify, so without this ceiling a busy
  // hub's known-dest flood keeps the crypto pipeline saturated forever.
  static const int _verifyBudgetPerWindow = 8;
  int _verifyWindowStart = 0;
  int _verifyCount = 0;

  bool _takeVerifyToken() {
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    if (nowMs - _verifyWindowStart >= _annBudgetWindowMs) {
      _verifyWindowStart = nowMs;
      _verifyCount = 0;
    }
    if (_verifyCount >= _verifyBudgetPerWindow) return false;
    _verifyCount++;
    return true;
  }

  // Announce name_hashes (10-byte, hex) that must NEVER be shed by the budget —
  // our OWN overlay's destinations (e.g. Aurora chat/files/dht/relay). They're
  // rare in the public-hub flood but essential for peer discovery; the host
  // fills this with RnsDestination.nameHash(app, aspects) for each. The name
  // hash is a constant per app+aspects, so one cheap lookup identifies them
  // without verifying the signature.
  final Set<String> priorityAnnounceNames = {};
  // Offset of the 10-byte name_hash in announce data: after the 64-byte pubkey.
  static const int _annPubkeyLen = 64;
  static const int _annNameHashLen = 10;

  bool _isPriorityAnnounce(RnsPacket p) {
    if (priorityAnnounceNames.isEmpty) return false;
    final d = p.data;
    if (d.length < _annPubkeyLen + _annNameHashLen) return false;
    final nh = _hex(Uint8List.sublistView(
        d, _annPubkeyLen, _annPubkeyLen + _annNameHashLen));
    return priorityAnnounceNames.contains(nh);
  }
  final Set<String> _seenPackets = {};
  // Link table for transport forwarding: link_id hex -> the two interfaces the
  // link bridges (created when we forward a LINKREQUEST). Lets us route every
  // subsequent link-addressed packet (proof, link data, resource) both ways.
  final Map<String, _LinkRoute> _linkTable = {};
  static const int _maxLinkRoutes = 4096;
  static const int _linkRouteTtlMs = 3600 * 1000; // 1h idle

  // ── Passive (leaf) mode under CPU pressure ───────────────────────────────
  // Relaying the whole public-hub announce flood (rebroadcasting every inbound
  // announce onto every other interface, plus link/resource transit) is what
  // pegs a phone CPU and ANRs the app. When the inbound announce rate shows the
  // node can't afford that work, it drops to PASSIVE: it stays connected to all
  // hubs and keeps announcing + receiving its OWN traffic (the hubs do the
  // relaying), but stops relaying OTHER nodes' traffic. It auto-resumes when the
  // network quiets. This keeps a constrained device usable without leaving the
  // mesh — exactly the real-world "my CPU can't take it, so go passive" case.
  bool _passive = false;
  bool get passive => _passive;

  /// When true (default), [passive] is managed automatically from the observed
  /// announce load. Set false to pin the mode (manual override / tests).
  bool autoPassive = true;

  /// Force passive on/off (also stops auto-management until re-enabled).
  void setPassive(bool value, {bool auto = false}) {
    autoPassive = auto;
    if (_passive != value) {
      _passive = value;
      log?.call('passive ${value ? 'ON (manual)' : 'OFF (manual)'}');
    }
  }

  // Inbound-announce-rate sampler (the relay-work proxy: relay cost rises with
  // announces/sec × interface count). Sampled even while passive so we can tell
  // when the flood has subsided enough to safely resume relaying. Hysteresis: go
  // passive after a few sustained high-rate seconds, resume after a longer calm.
  static const int _loadHighPerSec = 50; // above → relaying would peg a phone
  static const int _loadLowPerSec = 12;  // below → relaying is affordable again
  static const int _overSecsToPassive = 3;
  static const int _underSecsToActive = 10;
  int _loadWinStartMs = 0;
  int _annInWin = 0;
  int _overSecs = 0;
  int _underSecs = 0;
  double _lastAnnPerSec = 0;

  /// Most recent measured inbound announce rate (announces/second).
  double get announceRatePerSec => _lastAnnPerSec;

  void _accountAnnounceLoad() {
    final now = DateTime.now().millisecondsSinceEpoch;
    if (_loadWinStartMs == 0) _loadWinStartMs = now;
    _annInWin++;
    final elapsed = now - _loadWinStartMs;
    if (elapsed < 1000) return;
    final perSec = _annInWin * 1000 / elapsed;
    _lastAnnPerSec = perSec;
    _loadWinStartMs = now;
    _annInWin = 0;
    if (!autoPassive) return;
    if (perSec >= _loadHighPerSec) {
      _underSecs = 0;
      _overSecs++;
      if (!_passive && _overSecs >= _overSecsToPassive) {
        _passive = true;
        log?.call(
            'passive ON — announce flood ${perSec.round()}/s, shedding relay to save CPU');
      }
    } else if (perSec <= _loadLowPerSec) {
      _overSecs = 0;
      _underSecs++;
      if (_passive && _underSecs >= _underSecsToActive) {
        _passive = false;
        log?.call(
            'passive OFF — announce load ${perSec.round()}/s, resuming relay');
      }
    } else {
      _overSecs = 0;
      _underSecs = 0;
    }
  }

  RnsTransport({this.log, this.transportId});

  int get pathCount => _paths.length;

  /// Read-only view of every path entry — the transport engine's mirror sweep
  /// iterates this to push recently-updated entries to its client.
  Iterable<RnsPathEntry> get pathsView => _paths.values;
  Iterable<RnsPathEntry> get paths => _paths.values;
  // A relaying transport node only when it has a relay id AND isn't shedding
  // load. In passive mode it still announces/receives its own traffic.
  bool get isTransportNode => transportId != null && !_passive;

  @override
  void addInterface(RnsInterface iface) => _interfaces.add(iface);
  @override
  void removeInterface(RnsInterface iface) =>
      _interfaces.removeWhere((i) => identical(i, iface));

  /// Originate a locally-produced packet on every interface (e.g. our own
  /// announce). Inbound relaying uses [ingest]'s rebroadcast instead.
  void sendOnAll(Uint8List raw) {
    for (final i in _interfaces) {
      i.send(raw);
    }
  }

  // The interface label a given link's traffic flows on (link_id hex -> label),
  // learned from inbound link packets. A link is sticky to the path it was
  // established on, so its DATA/parts must go out ONLY there — broadcasting link
  // traffic on every interface multiplies our uplink load (e.g. 5 hubs => 5x),
  // which on a phone saturates the uplink and stalls a large Resource transfer.
  final Map<String, String> _linkIface = {};
  final List<String> _linkIfaceOrder = [];
  static const int _maxLinkIface = 512;

  /// Record that link [linkId] is reachable on interface [via] (called for every
  /// inbound link-addressed packet).
  /// Which interface a link arrived on ('lan', 'ble', a hub name…), or null.
  /// An Archiver reads this: a peer that reached us over a direct link has no
  /// route to anywhere else, and that fact IS the policy.
  String? ifaceOfLink(Uint8List linkId) => _linkIface[_hex(linkId)];

  void noteLinkIface(Uint8List linkId, String via) {
    final k = _hex(linkId);
    final cur = _linkIface[k];
    if (cur == via) return;
    // A link's setup packets (LRPROOF/LRRTT) can arrive on MORE than one
    // interface — the request went out on all of them, so the peer may answer on
    // each. Keep the FASTEST interface, not merely the last one seen: otherwise a
    // slow/flaky hub copy arriving after the good LAN copy would flip subsequent
    // link DATA (GET_FILE, resource) onto the hub and the transfer would stall.
    if (cur != null && _speedRank(cur) > _speedRank(via)) return;
    if (cur == null) {
      _linkIfaceOrder.add(k);
      if (_linkIfaceOrder.length > _maxLinkIface) {
        _linkIface.remove(_linkIfaceOrder.removeAt(0));
      }
    }
    _linkIface[k] = via;
  }

  /// Send a locally-produced packet, routing LINK-addressed traffic on the single
  /// interface that link uses (if known); everything else goes on all interfaces.
  /// This is the right default for file/relay/lxmf link traffic — it keeps a big
  /// Resource transfer from being multiplied across every hub uplink.
  void sendLinkAware(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p != null) {
      // Established link traffic: stick to the interface that link flows on.
      if (p.destType == RnsDestType.link) {
        final label = _linkIface[_hex(p.destHash)];
        if (label != null) {
          final iface = _ifaceByLabel(label);
          if (iface != null) {
            iface.send(raw);
            return;
          }
        }
      }
      // Transport-addressed (HEADER_2) traffic — e.g. a LINKREQUEST to a remote
      // destination — must go out ONLY on the interface where that dest's path
      // was learned, exactly like reference RNS (Transport.outbound sends on
      // path.receiving_interface). Broadcasting it on every hub emits duplicate
      // copies with the same packet hash; RNS's dedup at intermediate nodes can
      // then drop the copy travelling the good route before it reaches the
      // holder, so the link never establishes even with a valid path.
      if (p.headerType == RnsHeaderType.header2) {
        final path = pathFor(p.destHash);
        if (path != null) {
          final iface = _ifaceByLabel(path.via);
          if (iface != null) {
            iface.send(raw);
            return;
          }
        }
      }
      // A HEADER_1 link REQUEST (destType single) normally goes out on ALL
      // interfaces (below): the handshake must round-trip, and a shared-medium
      // LAN can be ASYMMETRIC (A's subnet broadcasts reach B but not vice-versa
      // — AP broadcast filtering), so pinning to the LAN could black-hole it.
      // EXCEPTION: a top-rank (≥4) interface is a dedicated point-to-point pipe
      // — a WiFi-Direct P2P link — which is symmetric by construction and has no
      // hub fallback to preserve. Pin the request to it so the RESPONDER hears
      // it over that link and confirms the link's large MTU; otherwise the peer
      // accepts a duplicate that arrived over a 500-MTU medium first and the two
      // ends disagree on MTU, stalling the resource transfer.
      if (p.destType == RnsDestType.single) {
        final path = pathFor(p.destHash);
        if (path != null && _speedRank(path.via) >= 4) {
          final iface = _ifaceByLabel(path.via);
          if (iface != null) {
            iface.send(raw);
            return;
          }
        }
      }
    }
    sendOnAll(raw);
  }

  RnsPathEntry? pathFor(Uint8List destHash) => _paths[_hex(destHash)];
  bool hasPath(Uint8List destHash) => _paths.containsKey(_hex(destHash));

  /// The hardware MTU of the interface a packet to [destHash] would leave on —
  /// used by the link initiator to offer a larger link MTU (RNS link MTU
  /// discovery / Transport.next_hop_interface_hw_mtu). Falls back to [kRnsMtu]
  /// when no path/interface is known (i.e. no discovery).
  int nextHopInterfaceHwMtu(Uint8List destHash) {
    final path = pathFor(destHash);
    if (path == null) return kRnsMtu;
    return _ifaceByLabel(path.via)?.hardwareMtu ?? kRnsMtu;
  }

  /// HW MTU of the interface labelled [via] (the one a packet just arrived on) —
  /// used by the responder to cap the link MTU it confirms to what its return
  /// path can carry. Falls back to [kRnsMtu] for unknown labels.
  int hwMtuForVia(String via) => _ifaceByLabel(via)?.hardwareMtu ?? kRnsMtu;

  /// Originate a single connectionless DATA packet addressed to [destHash]
  /// (already-encrypted [data]), routed via our path table: HEADER_2 to the
  /// next-hop transport node if we hold one, else HEADER_1 broadcast for the
  /// directly-attached hub to forward toward the destination. Used for
  /// connectionless app delivery to a SINGLE destination (e.g. a circles
  /// rendezvous join request) WITHOUT a link handshake — one packet, so it
  /// survives an asymmetric inbound far better than a 3-way link setup.
  void sendDataTo(Uint8List destHash, Uint8List data,
          {int context = RnsContext.none}) =>
      _sendConnectionless(destHash, data,
          context: context, destType: RnsDestType.single);

  /// Send one connectionless PLAIN packet to [destHash] — no link, no handshake,
  /// no Reticulum-layer encryption (the payload carries its own, e.g. an NPD
  /// probe encrypted to the peer's NOSTR key).
  ///
  /// Routes multi-hop exactly like any other packet: when we hold a path with a
  /// next hop, this goes out HEADER_2 transport-addressed, and a transport node's
  /// [_maybeForward] relays it while [_forwardToward] preserves the dest type.
  /// With no known path it falls back to a HEADER_1 broadcast, which only
  /// reaches directly-attached neighbours.
  void sendPlainTo(Uint8List destHash, Uint8List data,
          {int context = RnsContext.none}) =>
      _sendConnectionless(destHash, data,
          context: context, destType: RnsDestType.plain);

  void _sendConnectionless(Uint8List destHash, Uint8List data,
      {required int context, required int destType}) {
    final path = _paths[_hex(destHash)];
    final toTransport = path?.nextHop != null;
    final pkt = RnsPacket(
      destHash: destHash,
      data: data,
      headerType:
          toTransport ? RnsHeaderType.header2 : RnsHeaderType.header1,
      transportType: toTransport
          ? RnsTransportType.transport
          : RnsTransportType.broadcast,
      destType: destType,
      packetType: RnsPacketType.data,
      context: context,
      transportId: toTransport ? path!.nextHop : null,
    );
    sendOnAll(pkt.pack());
  }

  /// Diagnostic: the routing details of our path to [destHash] (next hop, the
  /// interface we'd forward on, hops, age). Null if we hold no path.
  Map<String, dynamic>? pathInfo(Uint8List destHash) {
    final e = _paths[_hex(destHash)];
    if (e == null) return null;
    return {
      'nextHop': e.nextHop == null ? null : _hex(e.nextHop!),
      'via': e.via,
      'hops': e.hops,
      'ageMs': DateTime.now().millisecondsSinceEpoch - e.updatedMs,
      'identity': _hex(e.identity.hash),
    };
  }

  /// Diagnostic: labels of the live interfaces (the hubs/links we forward on).
  List<String> get interfaceLabels => [for (final i in _interfaces) i.label];

  // ── Path requests (pull path-finding) ───────────────────────────────────
  // The well-known RNS path-request destination: PLAIN "rnstransport.path.request"
  // → truncated_hash(name_hash). Asking this destination for a path is the PULL
  // half of RNS path-finding: a peer (or a hub the target is a local client of)
  // answers with the target's announce (context PATH_RESPONSE), which ingest()
  // learns as an ordinary announce. This reaches a destination whose announce
  // never passively flooded to us (busy/asymmetric public hubs) — the hub the
  // target is directly attached to answers on our direct link.
  static final Uint8List _pathRequestDest = RnsCrypto.truncatedHash(
      RnsDestination.nameHash('rnstransport', ['path', 'request']));

  /// True when [raw] is a path-request packet (PLAIN/DATA to the well-known
  /// path-request destination). Interfaces use this to treat path requests as
  /// DISCOVERY (broadcast like an announce) rather than data.
  static bool isPathRequest(Uint8List raw) {
    if (raw.length < 18) return false;
    if ((raw[0] & 0x03) != RnsPacketType.data) return false;
    for (var i = 0; i < 16; i++) {
      if (raw[2 + i] != _pathRequestDest[i]) return false;
    }
    return true;
  }

  /// Called (rate-limited) with the requested destination hash of an inbound
  /// path request. The host answers by re-announcing when the dest is its own.
  void Function(Uint8List destHash)? onPathRequest;
  int _lastPathAnswerMs = 0;
  final Random _rng = Random.secure();

  // ── Asking for a path costs the whole radio ──────────────────────────────
  //
  // A path request is a broadcast on EVERY interface. It is cheap on a hub
  // uplink and it is the entire medium on Bluetooth, so the cost of asking has
  // to be paid once, not on every attempt by every subsystem that wants the
  // same peer.
  //
  // Measured on two phones with no internet: the same six destinations were
  // requested six times every twelve milliseconds, for hours. The node held 49
  // DHT peers cached from when it had Wi-Fi, none of them reachable over the one
  // radio it had left, and every subsystem that wanted one asked again on every
  // pass. That storm pegged a full core on both phones (load average 21 on the
  // weaker one), starved the beacon down to one per 75 seconds, drowned the
  // advert channel, and flooded the log ring so hard it only held two minutes of
  // history. Nothing was delivered while it ran.
  //
  // So the answer is remembered — including the silence, which is the common
  // case (docs/performance.md, "cache the miss, not just the hit"). One ask per
  // destination, then a doubling wait while nobody answers, cleared the moment a
  // path lands.
  final Map<String, _AskState> _asked = {};

  /// First wait after an unanswered ask. A path response from a live neighbour
  /// arrives in well under a second, so this is already generous.
  static const int _askBackoffMinMs = 15 * 1000;

  /// Ceiling on the doubling. A peer that has not answered in five minutes is
  /// not one more request away.
  static const int _askBackoffMaxMs = 5 * 60 * 1000;

  /// Total asks per minute across every destination, whatever the callers do.
  /// The radio is shared with everything else this device says.
  static const int _askesPerMinute = 20;
  final List<int> _askAt = [];

  int _askSuppressed = 0;

  /// Path requests held back by the backoff (diagnostics).
  int get pathRequestsSuppressed => _askSuppressed;

  /// A path arrived: forget the backoff so the next genuine need asks at once.
  void _clearAsk(String key) => _asked.remove(key);

  /// Ask the network for a path to [destHash]. Best-effort, fire-and-forget;
  /// the response arrives asynchronously as a PATH_RESPONSE announce.
  ///
  /// Rate-limited per destination and globally — see [_asked]. Pass
  /// [force] for a request a person is waiting on (a delivery that just failed),
  /// which still respects the global cap but ignores the per-destination wait.
  void requestPath(Uint8List destHash, {bool force = false}) {
    if (_interfaces.isEmpty) return;
    final key = _hex(destHash);
    final nowMs = DateTime.now().millisecondsSinceEpoch;

    _askAt.removeWhere((t) => nowMs - t > 60000);
    if (_askAt.length >= _askesPerMinute) {
      _askSuppressed++;
      return;
    }

    final st = _asked[key];
    if (st != null && !force && nowMs < st.nextMs) {
      _askSuppressed++;
      return;
    }
    final waitMs = st == null
        ? _askBackoffMinMs
        : (st.waitMs * 2 > _askBackoffMaxMs ? _askBackoffMaxMs : st.waitMs * 2);
    _asked[key] = _AskState(nextMs: nowMs + waitMs, waitMs: waitMs);
    if (_asked.length > 512) _asked.remove(_asked.keys.first);
    _askAt.add(nowMs);
    final tag = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      tag[i] = _rng.nextInt(256);
    }
    // transport-enabled form: dest_hash(16) + our_transport_id(16) + tag(16).
    final data = BytesBuilder();
    data.add(destHash);
    data.add(transportId ?? Uint8List(16));
    data.add(tag);
    final pkt = RnsPacket(
      destHash: _pathRequestDest,
      data: data.toBytes(),
      headerType: RnsHeaderType.header1,
      transportType: RnsTransportType.broadcast,
      destType: RnsDestType.plain,
      packetType: RnsPacketType.data,
      context: RnsContext.none,
      hops: 0,
    );
    sendOnAll(pkt.pack());
    log?.call('path request -> ${_hex(destHash)}');
  }

  /// A path we routed on did not deliver. Forget it and go looking again.
  ///
  /// Nothing else in this table learns from failure. A path is installed by an
  /// announce and replaced only by a better announce, so a route that has died
  /// — the classic case is a phone that was on Wi-Fi when we learned it and is
  /// now on Bluetooth only — stays installed and every message to that peer is
  /// posted into it. Observed on device: a peer one BLE hop away, addressed
  /// through a 5-hop internet hub for fifty minutes, seven deliveries timed out
  /// in a row, and the hub route was still there because no announce had come
  /// to displace it (it could not: the peer had no internet left to announce
  /// over, and its Bluetooth announces lost the rank comparison).
  ///
  /// So delivery failure is evidence, and this is where it lands: drop the
  /// entry, drop the identity pin that would re-point siblings back at the same
  /// dead interface, and ask the network again. A peer in the room answers the
  /// path request over the radio we actually share with it, and the fresh
  /// announce installs a path that works. Costs one path request; a wrong guess
  /// is repaired by the next announce.
  ///
  /// Returns true when something was actually forgotten.
  bool pathFailed(Uint8List destHash, {String reason = ''}) {
    final key = _hex(destHash);
    final entry = _paths.remove(key);
    if (entry != null) {
      final idHex = _hex(entry.identity.hash);
      _identityFastVia.remove(idHex);
      // Siblings of the same peer point at the same dead interface, and the
      // next send would pick one of them. Take them all down together.
      _paths.removeWhere(
          (_, e) => _hex(e.identity.hash) == idHex && e.via == entry.via);
      log?.call('path ${key.substring(0, 8)} via ${entry.via} '
          '(${entry.hops} hops) dropped after failure'
          '${reason.isEmpty ? "" : ": $reason"} — asking again');
    }
    // A person is waiting on THIS one, and the route we had is gone: it jumps
    // the per-destination backoff (the global cap still applies).
    requestPath(destHash, force: true);
    return entry != null;
  }

  /// Whether the interface with [label] is announce-only (discovery, no data).
  /// Unknown labels (e.g. a removed interface) are treated as data-capable so a
  /// stale entry is never wrongly preferred or dropped.
  bool _isAnnounceOnly(String label) {
    for (final i in _interfaces) {
      if (i.label == label) return i.announceOnly;
    }
    return false;
  }

  // Fastest data-capable interface we've heard each identity's announces on
  // (identityHex -> interface label). Lets a dest whose own (broadcast) announce
  // was lost still route over the LAN when a SIBLING dest of the same node was
  // heard there — co-located transfer no longer depends on every dest's beacon.
  // The fastest data-capable interface we have RECENTLY heard an identity on.
  // This is a claim about where a peer *is*, so it must expire: a peer that
  // leaves the LAN (phone moves to cellular / another AP) is no longer reachable
  // there, and a stale pin silently black-holes every packet we send it — the
  // rank rule in the path logic refuses to replace a "fast" LAN path with the
  // slower hub path we can actually reach it on, so the pin never self-heals and
  // the peer stays unreachable until the app restarts.
  final Map<String, _FastVia> _identityFastVia = {};

  /// A pin is trusted only while the peer keeps being heard on that interface.
  /// Must comfortably exceed the slowest announce cadence (5 min on battery /
  /// cellular) so a quiet-but-present LAN peer is not demoted for merely being
  /// slow to re-announce.
  static const int _fastViaTtlMs = 12 * 60 * 1000;

  /// Announces of this identity heard on a SLOWER medium with not one on the
  /// pinned interface in between. The peer has almost certainly left that
  /// medium. Heals faster than the wall-clock TTL when announces are frequent.
  /// A false demote is cheap (traffic takes the hub — slower but WORKING) while
  /// a false pin is a black hole, so this deliberately errs toward demoting.
  static const int _fastViaMaxMisses = 4;

  int _speedRank(String label) {
    for (final i in _interfaces) {
      if (i.label == label) return i.speedRank;
    }
    return 2;
  }

  /// Public speed-rank of the interface labelled [label] (2 if unknown).
  int speedRankOf(String label) => _speedRank(label);

  /// Repoint every path of [idHex] that a now-stale pin had aimed at
  /// [staleVia] onto [newVia] — the interface we are actually still hearing the
  /// peer on.
  ///
  /// Dropping the pin is NOT sufficient on its own: the path entries it already
  /// wrote still say `via: <fast medium>`, and the same-capability rank rule
  /// below refuses to replace a faster-ranked entry with a slower-ranked one. So
  /// the dead LAN path would outrank — and keep shadowing — the live hub path
  /// forever. Every destination of an identity shares one next hop (see
  /// [nextHopForIdentity]), so repointing them all is sound.
  void _demoteIdentityPaths(String idHex, String staleVia, String newVia,
      Uint8List? newNextHop, int newHops, int nowMs) {
    for (final e in _paths.values) {
      if (e.via != staleVia) continue;
      if (_hex(e.identity.hash) != idHex) continue;
      e.via = newVia;
      e.nextHop = newNextHop;
      e.hops = newHops;
      e.updatedMs = nowMs;
    }
  }

  /// A duplicate announce arrived on interface [via]. The dedup hash ignores
  /// hops/header/transportId, so this is the normal fate of the second copy of
  /// EVERY announce a co-located peer sends (LAN broadcast + hub rebroadcast
  /// race). It must therefore carry the same path-learning weight as a fresh
  /// announce — the old version repointed one destination and nothing else,
  /// which let the hub-first race starve the identity pin: pin.misses grew on
  /// every hub-first announce, hit the limit, and _demoteIdentityPaths rewrote
  /// LIVE LAN paths onto the hub with a non-null nextHop. The next LXMF link
  /// request then went out HEADER_2 on the hub uplink alone, and the hub does
  /// not cross-forward between clients: a silent black hole, healed only by the
  /// 90s LAN beacon — the exact 0.6s/30-60s flip-flop observed on device.
  ///
  /// No signature re-verify (identical signed packet) and no rebroadcast.
  ///
  /// Returns true when this copy has been dealt with. FALSE asks the caller to
  /// run the full ingest instead — the one case being a destination we hold no
  /// path for at all, where the shortcut has nothing to upgrade and dropping
  /// the copy would leave the peer unreachable until its next announce. That
  /// matters after [pathFailed] has just dropped a dead route: the copies still
  /// arriving are the fastest way to get a working one back.
  bool _maybeUpgradePath(RnsPacket p, String via) {
    if (p.packetType != RnsPacketType.announce) return true;
    if (_isAnnounceOnly(via)) return true; // can't carry data — never a path
    final key = _hex(p.destHash);
    final existing = _paths[key];
    if (existing == null) return false; // nothing to upgrade — ingest it fully
    final idHex = _hex(existing.identity.hash);
    final nowMs = DateTime.now().millisecondsSinceEpoch;

    // The peer IS still on the pinned interface — this copy proves it. Refresh
    // the pin's liveness even when nothing needs repointing, so hub-first races
    // stop accumulating misses toward a false demotion.
    final pin = _identityFastVia[idHex];
    if (pin != null && pin.label == via) {
      pin.heardMs = nowMs;
      pin.misses = 0;
    }

    if (existing.via == via) return true;
    if (_isAnnounceOnly(existing.via)) return true; // handled by the main path logic
    // A peer we hear DIRECTLY (hops 0 — it is our own neighbour on this
    // interface) beats one reached through somebody else, whatever the medium
    // ranks. Speed decides between paths of equal directness; it must not
    // decide between "arrives" and "does not". A phone with no internet, heard
    // over Bluetooth right next to us, was addressed through an internet hub —
    // because tcp outranks ble — and every message to it timed out while the
    // device sat there announcing itself a metre away.
    final direct = p.hops == 0;             // straight from the peer
    final existingDirect = existing.hops <= 1;
    // Never trade a neighbour we hear ourselves for a relayed copy of it, however
    // fast the relay's medium: the relay may have no way to reach that peer at
    // all (a Bluetooth-only phone, bridged onto the hubs by us).
    if (!direct && existingDirect) return true;
    if (!(direct && !existingDirect) &&
        _speedRank(via) <= _speedRank(existing.via)) {
      return true;
    }
    final nextHop =
        p.headerType == RnsHeaderType.header2 ? p.transportId : null;
    log?.call('path ${key.substring(0, 8)} ${existing.via} -> $via '
        '(rank ${_speedRank(existing.via)}->${_speedRank(via)}, '
        '${direct && !existingDirect ? "direct beats transported" : "upgrade"})');
    _paths.remove(key);
    _paths[key] = RnsPathEntry(
      destHash: existing.destHash,
      identity: existing.identity,
      publicKey: existing.publicKey,
      appData: existing.appData,
      hops: p.hops + 1,
      via: via,
      nextHop: nextHop,
      updatedMs: nowMs,
    );
    // And the identity-level work a fresh announce would have done: pin the
    // fast interface and pull every sibling destination of this peer onto it,
    // so the NEXT link request (which follows its own dest's path) goes local.
    if (pin == null ||
        _speedRank(via) > _speedRank(pin.label) ||
        (direct && !existingDirect)) {
      _identityFastVia[idHex] = _FastVia(via, nowMs);
      for (final e in _paths.values) {
        if (_hex(e.identity.hash) == idHex &&
            _speedRank(via) > _speedRank(e.via)) {
          e.via = via;
          e.nextHop = null;
          e.hops = 1;
          e.updatedMs = nowMs;
        }
      }
    }
    // (The isolate mirror learns these on its ≤2s sweep — well inside budget.)
    return true;
  }

  /// The next-hop transport for reaching [identity]'s destinations. A peer
  /// announces one destination (e.g. its chat dest), but every destination of
  /// that identity is reached via the same next hop, so we look up by identity.
  /// Returns null when the peer is a direct neighbour (single hop) or unknown.
  Uint8List? nextHopForIdentity(RnsIdentity identity) {
    final want = _hex(identity.hash);
    for (final e in _paths.values) {
      if (_hex(e.identity.hash) == want) return e.nextHop;
    }
    return null;
  }

  /// Ingest an inbound packet that arrived on interface [via]. Validates
  /// announces, updates the path table, and (if a transport node) rebroadcasts
  /// the announce onto the other interfaces. Returns the validated announce or
  /// null.
  Future<RnsAnnounce?> ingest(RnsPacket p, String viaArg) async {
    // Dedup by packet hash (RNS uses the same hashable-part scheme).
    final ph = _hex(p.packetHash());
    if (_seenPackets.contains(ph)) {
      // A node sends the SAME announce packet on all of its interfaces, and the
      // announce hash deliberately excludes hops/headerType/transportId — so the
      // origin's LAN broadcast and the hub's rebroadcast of it are ONE hash, and
      // whichever lands first wins the full ingest. The second copy must still
      // be able to do everything path learning needs (repoint the path, refresh
      // the identity pin, upgrade siblings) or a hub-first race leaves the peer
      // routed through a hub that never cross-forwards — the 30-60s message
      // black hole observed live between two devices ON THE SAME LAN.
      // A copy we can still learn from: only when there is nothing at all for
      // this destination does it fall through to the full (verifying) ingest.
      if (_maybeUpgradePath(p, viaArg)) return null;
    }
    // NOTE the hash is remembered only once the packet is actually PROCESSED
    // (forwarded, or validated as an announce). Remembering it up front poisoned
    // the slot: when the first copy was shed by the flood budget or the verify
    // ceiling, the sibling copy on the other interface was treated as "already
    // seen" and the announce was lost on BOTH interfaces until the next cycle.
    void remember() {
      _seenPackets.add(ph);
      if (_seenPackets.length > 8192) {
        _seenPackets.remove(_seenPackets.first);
      }
    }

    if (p.packetType != RnsPacketType.announce) {
      // Answer path requests aimed at one of OUR destinations: between two
      // Dart nodes (no reference transport node in the middle) nobody else
      // will, and without an answer a LAN peer that missed our periodic
      // announce simply cannot open a link to us until the next one — up to 5
      // minutes on battery. The host decides whether the dest is ours and
      // re-announces; we only rate-limit and hand it up.
      if (p.packetType == RnsPacketType.data &&
          p.destType == RnsDestType.plain &&
          _eq(p.destHash, _pathRequestDest) &&
          p.data.length >= 16) {
        remember();
        final wanted = Uint8List.sublistView(p.data, 0, 16);
        final cb = onPathRequest;
        if (cb != null) {
          final nowMs = DateTime.now().millisecondsSinceEpoch;
          if (nowMs - _lastPathAnswerMs > 2000) {
            _lastPathAnswerMs = nowMs;
            cb(wanted);
          }
        }
        return null;
      }
      remember();
      // As a transport node, forward link/resource traffic that isn't for us —
      // unless we've dropped to passive (leaf) mode to shed CPU load.
      if (transportId != null && !_passive && _maybeForward(p, viaArg)) {
        return null;
      }
      return null;
    }

    // Sample the inbound announce rate (drives the passive-mode auto-switch).
    // Counted before the flood-shed below so it reflects true load, not what we
    // chose to process.
    _accountAnnounceLoad();

    // Connected to a busy transport hub, a phone leaf hears the WHOLE network's
    // announce stream — hundreds of new destinations a second. Verifying an
    // Ed25519 signature for each on the UI isolate pegs a core and ANRs the app.
    // So budget the verification of *new* destinations over a small window;
    // re-announces of destinations we already track are cheap (see trustIf) and
    // never throttled, so paths we actually use keep refreshing. A dropped new
    // announce costs nothing — that destination re-announces periodically and
    // outbound traffic reaches the hub regardless.
    final destKey = _hex(p.destHash);
    // Exempt our own overlay's announces from the flood budget — otherwise the
    // rare Aurora announces get shed amid hundreds of foreign ones a second and
    // nodes never learn each other's routes (no media fetch, no FEED backfill).
    if (!_paths.containsKey(destKey) &&
        !_isPriorityAnnounce(p) &&
        p.context != RnsContext.pathResponse) {
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      if (nowMs - _annWindowStart >= _annBudgetWindowMs) {
        _annWindowStart = nowMs;
        _annCount = 0;
      }
      if (_annCount >= _annBudgetPerWindow) return null; // shed the flood
      _annCount++;
    }

    // Skip re-verifying an unchanged re-announce of a destination we already
    // verified (same key + app_data) — the common case once the table is warm.
    bool trusted(Uint8List dh, Uint8List pk, Uint8List ad) {
      final e = _paths[_hex(dh)];
      return e != null && _eq(e.publicKey, pk) && _eq(e.appData, ad);
    }

    // Anything that will need REAL crypto (trust fast-path miss) draws from the
    // global verify budget — known-dest re-announces with churned app_data and
    // priority announces included. Exhausted budget = shed the packet; the
    // destination re-announces periodically, nothing is lost but freshness.
    final needsCrypto = !wouldTrustAnnounce(p, trusted);
    if (needsCrypto && !_takeVerifyToken()) return null;

    final ann = await validateAnnounce(p, trustIf: trusted);
    if (ann == null) return null;
    remember(); // processed for real — only now may the sibling copy be a dup

    var pathHops = p.hops + 1; // hop just taken to reach us
    // If the announce arrived relayed (HEADER_2), the relayer's id is the next
    // hop toward this destination; a direct (HEADER_1) announce is a neighbour.
    var nextHop =
        p.headerType == RnsHeaderType.header2 ? p.transportId : null;
    var via = viaArg;
    // Identity-level LAN reachability. A node's per-destination announces ride
    // unreliable Wi-Fi BROADCAST, so this specific dest's LAN announce may be
    // lost while ANOTHER of the same node's dests (chat/lxmf) was heard over the
    // LAN — leaving this dest stuck on a slow hub path even though the node is a
    // direct LAN neighbour. If we've heard THIS identity over a fast direct
    // medium, treat this dest as reachable there too: a direct 1-hop path on
    // that interface (the LAN peer table already knows the node's address to
    // unicast to). This is what makes co-located transfer use the LAN reliably
    // instead of depending on every single dest's broadcast landing.
    //
    // The pin is EVIDENCE, not a fact: it says "we heard this peer there", and
    // a peer can leave. Age it against the announces we keep hearing, and when
    // it goes stale, demote the paths it pinned (see [_demoteIdentityPaths] for
    // why removing the pin alone is not enough).
    final idHex = _hex(ann.identity.hash);
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    final pin = _identityFastVia[idHex];
    if (pin != null) {
      if (viaArg == pin.label) {
        pin.heardMs = nowMs; // still there — refresh liveness
        pin.misses = 0;
      } else if (_speedRank(viaArg) < _speedRank(pin.label)) {
        pin.misses++; // heard only on a slower medium: it may have moved
      }
      if (nowMs - pin.heardMs > _fastViaTtlMs ||
          pin.misses >= _fastViaMaxMisses) {
        _identityFastVia.remove(idHex);
        log?.call('path pin ${idHex.substring(0, 8)} ${pin.label} -> $viaArg '
            '(stale: peer no longer heard on ${pin.label})');
        _demoteIdentityPaths(idHex, pin.label, viaArg, nextHop, pathHops, nowMs);
      }
    }
    final fast = _identityFastVia[idHex];
    if (fast != null &&
        _speedRank(fast.label) > _speedRank(via) &&
        _ifaceByLabel(fast.label) != null) {
      via = fast.label;
      nextHop = null;
      pathHops = 1;
    }
    // Record the fastest data-capable interface we've heard this identity on, so
    // later announces of its OTHER dests can be upgraded to it (above). When it
    // gets FASTER, proactively upgrade EVERY already-known path of this identity
    // to that interface right now — otherwise a sibling dest whose own (rare,
    // broadcast) announce already landed on the hub would stay stuck there until
    // its next announce, and those are minutes apart / often dropped.
    if (!_isAnnounceOnly(viaArg)) {
      final cur = _identityFastVia[idHex];
      if (cur == null || _speedRank(viaArg) > _speedRank(cur.label)) {
        _identityFastVia[idHex] = _FastVia(viaArg, nowMs);
        for (final e in _paths.values) {
          if (_hex(e.identity.hash) == idHex &&
              _speedRank(viaArg) > _speedRank(e.via)) {
            e.via = viaArg;
            e.nextHop = null;
            e.hops = 1;
            e.updatedMs = nowMs;
          }
        }
      }
    }
    final key = _hex(ann.destHash);
    final existing = _paths[key];
    // Path preference. A path's usefulness for DATA depends on whether the
    // interface it was heard on can carry data: the LAN UDP interface is
    // announce-only (it drops all non-announce packets), so a path learned there
    // can never carry a link/DHT/file transfer. Such a path must NOT shadow a
    // data-capable (hub/TCP) path even though the LAN announce is fewer hops —
    // that shadowing made every link to a co-located peer time out. Rules:
    //   1. a data-capable ingest always replaces an announce-only entry (any hops);
    //   2. an announce-only ingest never overwrites a data-capable entry;
    //   3. within the same capability class, prefer fewer/equal hops (LRU refresh).
    final viaAnnounceOnly = _isAnnounceOnly(via);
    final existingAnnounceOnly =
        existing != null && _isAnnounceOnly(existing.via);
    final bool replace;
    if (existing == null) {
      replace = true;
    } else if (viaAnnounceOnly && !existingAnnounceOnly) {
      replace = false;
    } else if (!viaAnnounceOnly && existingAnnounceOnly) {
      replace = true;
    } else {
      // Same capability class: prefer the faster medium first (a direct LAN
      // path beats the internet hub AND BLE for a co-located peer), then
      // fewer/equal hops (equal = LRU refresh of the same-quality path).
      // Directness first: a neighbour we hear ourselves (hops 0) outranks a
      // peer reached through someone else, whatever medium each arrived on.
      // Otherwise the faster medium, then fewer/equal hops (equal = LRU
      // refresh of the same-quality path).
      final newRank = _speedRank(via);
      final oldRank = _speedRank(existing.via);
      // "Direct" = the peer itself put this on the wire and we heard it: one
      // hop taken to reach us, nobody in between.
      final newDirect = pathHops <= 1;
      final oldDirect = existing.hops <= 1;
      if (newDirect != oldDirect) {
        replace = newDirect;
      } else if (newRank != oldRank) {
        replace = newRank > oldRank;
      } else {
        replace = pathHops <= existing.hops;
      }
    }
    if (replace) {
      if (existing != null && existing.via != via) {
        log?.call('path ${_hex(ann.destHash).substring(0, 8)} '
            '${existing.via} -> $via (rank ${_speedRank(existing.via)}'
            '->${_speedRank(via)}, hops ${existing.hops}->$pathHops)');
      }
      // Re-insert at the tail so recently-heard destinations are youngest —
      // the table is an LRU bounded by [_maxPaths] (below) so the network-wide
      // announce flood can't grow it without bound (the old OOM).
      _paths.remove(key);
      _clearAsk(key); // answered — the next genuine need may ask immediately
      _paths[key] = RnsPathEntry(
        destHash: ann.destHash,
        identity: ann.identity,
        publicKey: ann.publicKey,
        appData: ann.appData,
        hops: pathHops,
        via: via,
        nextHop: nextHop,
        updatedMs: DateTime.now().millisecondsSinceEpoch,
      );
      // Evict the oldest entries past the cap (insertion order = age).
      while (_paths.length > _maxPaths) {
        _paths.remove(_paths.keys.first);
      }
    }

    // Relay the announce onward only as an active transport node. In passive
    // mode we still learned the path above and return the announce for local
    // delivery, but we don't carry the network's flood on our back.
    if (!_passive) _rebroadcast(p, ann, pathHops, via);
    return ann;
  }

  /// Transport-node forwarding of non-announce packets. Returns true if the
  /// packet was forwarded (i.e. it was transit traffic, not for this node):
  ///   - destType==LINK with a tracked route -> forward to the other interface
  ///     (proof, link data, resource — both directions);
  ///   - HEADER_2 addressed to us (transport_id==ours) -> forward toward the
  ///     destination's path next hop, and (for a LINKREQUEST) remember the link
  ///     so its reverse + data packets route back.
  bool _maybeForward(RnsPacket p, String via) {
    final myId = transportId;
    if (myId == null) return false;
    if (p.hops >= kRnsMaxHops) return false;

    // 1) A packet addressed to a link we bridge.
    if (p.destType == RnsDestType.link) {
      final route = _linkTable[_hex(p.destHash)];
      if (route == null) return false;
      final out = route.other(via);
      if (out == null) return false;
      route.touch();
      out.send(_reframeLink(p).pack());
      return true;
    }

    // 2) A transport-addressed packet whose next hop is us.
    if (p.headerType == RnsHeaderType.header2 &&
        p.transportId != null &&
        _eq(p.transportId!, myId) &&
        p.transportType == RnsTransportType.transport) {
      final path = _paths[_hex(p.destHash)];
      if (path == null) return false; // no route to the destination
      final outIface = _ifaceByLabel(path.via);
      if (outIface == null) return false;

      if (p.packetType == RnsPacketType.linkRequest) {
        final inIface = _ifaceByLabel(via);
        if (inIface != null) {
          _pruneLinkRoutes();
          _linkTable[_hex(RnsLink.linkIdFromRequest(p))] =
              _LinkRoute(inIface, outIface);
        }
      }
      outIface.send(_forwardToward(p, path).pack());
      return true;
    }
    return false;
  }

  // Forward a dest-addressed packet one hop toward [path]. If the destination is
  // a direct neighbour of the next node (path.nextHop == null) send HEADER_1
  // (consume the transport id); otherwise keep transport-addressing to the next
  // transport. hops is incremented.
  RnsPacket _forwardToward(RnsPacket p, RnsPathEntry path) {
    final toTransport = path.nextHop != null;
    return RnsPacket(
      destHash: p.destHash,
      data: p.data,
      headerType:
          toTransport ? RnsHeaderType.header2 : RnsHeaderType.header1,
      transportType: toTransport
          ? RnsTransportType.transport
          : RnsTransportType.broadcast,
      destType: p.destType,
      packetType: p.packetType,
      context: p.context,
      contextFlag: p.contextFlag,
      transportId: toTransport ? path.nextHop : null,
      hops: p.hops + 1,
    );
  }

  // Forward a link-addressed packet to the opposite side of the bridge. The next
  // node is a direct neighbour here (leaf-hub-leaf), so HEADER_1 by link_id; the
  // endpoint matches on the link_id regardless of header form.
  RnsPacket _reframeLink(RnsPacket p) => RnsPacket(
        destHash: p.destHash, // = link_id
        data: p.data,
        headerType: RnsHeaderType.header1,
        transportType: RnsTransportType.broadcast,
        destType: RnsDestType.link,
        packetType: p.packetType,
        context: p.context,
        contextFlag: p.contextFlag,
        hops: p.hops + 1,
      );

  RnsInterface? _ifaceByLabel(String label) {
    for (final i in _interfaces) {
      if (i.label == label) return i;
    }
    return null;
  }

  void _pruneLinkRoutes() {
    final now = DateTime.now().millisecondsSinceEpoch;
    _linkTable.removeWhere((_, r) => now - r.lastMs > _linkRouteTtlMs);
    while (_linkTable.length >= _maxLinkRoutes) {
      _linkTable.remove(_linkTable.keys.first);
    }
  }

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  // Rebroadcast an announce onto every interface except the one it arrived on.
  void _rebroadcast(RnsPacket p, RnsAnnounce ann, int pathHops, String via) {
    final tid = transportId;
    if (tid == null) return;
    if (pathHops >= kRnsMaxHops) return;
    var others = _interfaces.where((i) => i.label != via);
    if (edgeBridge) {
      // Only carry announces heard on an edge (e.g. BLE local peers) and only
      // onto core interfaces — never re-air the internet flood onto BLE, and
      // never loop a hub announce across other hub uplinks.
      final viaIface = _ifaceByLabel(via);
      if (viaIface == null || !viaIface.edge) return;
      others = others.where((i) => !i.edge);
    }
    final targets = others.toList();
    if (targets.isEmpty) return;

    final relay = RnsPacket(
      destHash: ann.destHash,
      data: p.data,
      headerType: RnsHeaderType.header2,
      transportType: RnsTransportType.transport,
      destType: RnsDestType.single,
      packetType: RnsPacketType.announce,
      context: p.context,
      contextFlag: p.contextFlag,
      transportId: tid,
      hops: pathHops,
    );
    final raw = relay.pack();
    for (final iface in targets) {
      iface.send(raw);
      log?.call(
          'rebroadcast ${_hex(ann.destHash)} -> ${iface.label} hops=$pathHops');
    }
  }

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

/// A bridged link: the two interfaces a transit link's packets route between.
class _LinkRoute {
  final RnsInterface a;
  final RnsInterface b;
  int lastMs;
  _LinkRoute(this.a, this.b) : lastMs = DateTime.now().millisecondsSinceEpoch;

  /// The interface opposite to the one a packet arrived on ([viaLabel]).
  RnsInterface? other(String viaLabel) {
    if (viaLabel == a.label) return b;
    if (viaLabel == b.label) return a;
    return null;
  }

  void touch() => lastMs = DateTime.now().millisecondsSinceEpoch;
}

/// When we may next ask for a path to one destination, and how long we waited
/// last time (doubling while nobody answers).
class _AskState {
  const _AskState({required this.nextMs, required this.waitMs});
  final int nextMs;
  final int waitMs;
}
