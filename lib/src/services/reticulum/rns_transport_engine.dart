/*
 * RNS transport engine isolate.
 *
 * Phase 1a of moving the Reticulum node off the UI isolate: the PACKET PLANE —
 * RnsTransport with its announce validation (budgeted Ed25519 via the crypto
 * worker, which spawns per-isolate and therefore lives HERE), dedup, path
 * table, transit forwarding, rebroadcast fan-out and passive-mode governor —
 * runs in a dedicated isolate. A public-hub announce flood costs the UI
 * isolate nothing but the raw byte hand-off.
 *
 * The interfaces (sockets, radios) stay with the owner for now and are
 * registered here as EXTERNAL interfaces: the owner pumps inbound frames in
 * with [RnsTransportClient.ingestRaw] and outbound frames come back as tx
 * events dispatched to the real interface's send(). Stage B moves the
 * dart:io sockets in here too; the BLE/WiFi-Direct radios are plugin-bound to
 * the root isolate and will always bridge this way.
 *
 * The client mirrors the path table for the owner's many synchronous reads
 * (pathFor / hasPath / nextHopForIdentity / graph building): the engine pushes
 * an upsert after every accepted announce plus a 2s sweep of entries whose
 * updatedMs moved (sibling-path upgrades). The mirror is a routing HINT on the
 * client side — authoritative routing (rebroadcast, transit, link pinning)
 * happens in the engine, so brief mirror staleness is harmless.
 */
import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'rns_announce.dart';
import 'rns_identity.dart';
import 'rns_packet.dart';
import 'rns_transport.dart';

/// Main-isolate handle to the transport engine. Method names deliberately
/// mirror [RnsTransport] so the owner swaps types with minimal churn.
class RnsTransportClient implements RnsInterfaceRegistry {
  RnsTransportClient._(this.log);

  final void Function(String msg)? log;

  /// Validated announce arrived (post-budget, post-crypto). hops = wire hops.
  void Function(RnsAnnounce ann, int hops, String via)? onAnnounce;

  /// An inbound path request asked for a destination — forwarded from the
  /// engine so the host can answer for its OWN destinations (between two Dart
  /// nodes nobody else will). Rate-limited engine-side.
  void Function(Uint8List destHash)? onPathRequest;

  /// Engine stats push (~2s): passive flag, announce rate, path count.
  void Function()? onStats;

  SendPort? _cmd;
  Isolate? _iso;
  final Map<String, RnsInterface> _ifaces = {};
  final Map<String, RnsPathEntry> _pathMirror = {};
  static const int _mirrorCap = 2048;

  bool _passive = false;
  double _annRate = 0;
  Uint8List? _transportIdValue;
  bool _edgeBridgeValue = false;

  // ── lifecycle ─────────────────────────────────────────────────────────────

  static Future<RnsTransportClient> spawn({
    void Function(String msg)? log,
  }) async {
    final c = RnsTransportClient._(log);
    await c._start();
    return c;
  }

  Future<void> _start() async {
    final fromEngine = ReceivePort();
    final ready = Completer<void>();
    fromEngine.listen((msg) => _onEngineMessage(msg, ready));
    _iso = await Isolate.spawn(
      _engineMain,
      fromEngine.sendPort,
      debugName: 'rns-transport',
    );
  await ready.future.timeout(const Duration(seconds: 20));
  }

  void close() {
    _iso?.kill(priority: Isolate.immediate);
    _iso = null;
    _cmd = null;
  }

  void _onEngineMessage(Object? msg, Completer<void> ready) {
    if (msg is SendPort) {
      _cmd = msg;
      if (!ready.isCompleted) ready.complete();
      return;
    }
    if (msg is! List || msg.isEmpty) return;
    switch (msg[0] as String) {
      case 'tx':
        final iface = _ifaces[msg[1] as String];
        if (iface != null) {
          try {
            iface.send(msg[2] as Uint8List);
          } catch (_) {/* dead iface — owner reaps it via its own signals */}
        }
      case 'ann':
        final cb = onAnnounce;
        if (cb == null) return;
        final publicKey = msg[2] as Uint8List;
        final ann = RnsAnnounce(
          destHash: msg[1] as Uint8List,
          publicKey: publicKey,
          nameHash: msg[3] as Uint8List,
          appData: msg[4] as Uint8List,
          ratchet: msg[5] as Uint8List?,
          identity: RnsIdentity.fromPublicKey(publicKey),
        );
        try {
          cb(ann, msg[6] as int, msg[7] as String);
        } catch (_) {}
      case 'path':
        final publicKey = msg[2] as Uint8List;
        final destHash = msg[1] as Uint8List;
        final key = _hex(destHash);
        _pathMirror.remove(key); // re-insert at tail = LRU refresh
        _pathMirror[key] = RnsPathEntry(
          destHash: destHash,
          identity: RnsIdentity.fromPublicKey(publicKey),
          publicKey: publicKey,
          appData: msg[3] as Uint8List,
          hops: msg[4] as int,
          via: msg[5] as String,
          nextHop: msg[6] as Uint8List?,
          updatedMs: msg[7] as int,
        );
        while (_pathMirror.length > _mirrorCap) {
          _pathMirror.remove(_pathMirror.keys.first);
        }
      case 'pathreq':
        try {
          onPathRequest?.call(msg[1] as Uint8List);
        } catch (_) {}
      case 'stats':
        _passive = msg[1] as bool;
        _annRate = msg[2] as double;
        try {
          onStats?.call();
        } catch (_) {}
      case 'log':
        log?.call(msg[1] as String);
    }
  }

  void _send(List<Object?> cmd) => _cmd?.send(cmd);

  // ── config (mirrors RnsTransport fields) ──────────────────────────────────

  set transportId(Uint8List? id) {
    _transportIdValue = id;
    _send(['transportId', id]);
  }

  Uint8List? get transportId => _transportIdValue;

  set edgeBridge(bool v) {
    _edgeBridgeValue = v;
    _send(['edgeBridge', v]);
  }

  bool get edgeBridge => _edgeBridgeValue;

  void setPriorityAnnounceNames(Iterable<String> names) =>
      _send(['priorityNames', names.toList()]);

  void setPassive(bool value, {bool auto = false}) =>
      _send(['setPassive', value, auto]);

  bool get passive => _passive;
  double get announceRatePerSec => _annRate;

  // ── interfaces (external — sockets/radios stay with the owner) ───────────

  @override
  void addInterface(RnsInterface iface) {
    _ifaces[iface.label] = iface;
    _send([
      'ifaceAdd',
      iface.label,
      iface.speedRank,
      iface.hardwareMtu,
      iface.edge,
      iface.announceOnly,
    ]);
  }

  @override
  void removeInterface(RnsInterface iface) {
    _ifaces.remove(iface.label);
    _send(['ifaceRemove', iface.label]);
  }

  // ── packet plane ──────────────────────────────────────────────────────────

  /// Hand an inbound frame to the engine (announce validation, path learning,
  /// transit forwarding, rebroadcast). Fire-and-forget: validated announces
  /// come back via [onAnnounce].
  void ingestRaw(Uint8List raw, String via) => _send(['ingest', raw, via]);

  void sendOnAll(Uint8List raw) => _send(['sendOnAll', raw]);

  void sendLinkAware(Uint8List raw) => _send(['sendLinkAware', raw]);

  void noteLinkIface(Uint8List linkId, String via) =>
      _send(['noteLinkIface', linkId, via]);

  /// Ask for a path. Rate-limited per destination inside the engine; [force]
  /// is for a request somebody is waiting on (see [RnsTransport.requestPath]).
  void requestPath(Uint8List destHash, {bool force = false}) =>
      _send(['requestPath', destHash, force]);

  /// Report that routing to [destHash] failed to deliver — see
  /// [RnsTransport.pathFailed]. The engine forgets the entry and asks again;
  /// the mirror drops it here so the owner's next synchronous read does not
  /// hand the same dead route straight back out.
  void pathFailed(Uint8List destHash, {String reason = ''}) {
    final key = _hex(destHash);
    final gone = _pathMirror.remove(key);
    if (gone != null) {
      // Siblings of the same peer ride the same dead interface.
      final idHex = _hex(gone.identity.hash);
      _pathMirror.removeWhere(
          (_, e) => _hex(e.identity.hash) == idHex && e.via == gone.via);
    }
    _send(['pathFailed', destHash, reason]);
  }

  void sendDataTo(Uint8List destHash, Uint8List data,
          {int context = RnsContext.none}) =>
      _send(['sendDataTo', destHash, data, context]);

  /// Connectionless PLAIN packet — see [RnsTransport.sendPlainTo].
  void sendPlainTo(Uint8List destHash, Uint8List data,
          {int context = RnsContext.none}) =>
      _send(['sendPlainTo', destHash, data, context]);

  // ── path reads (mirror) ───────────────────────────────────────────────────

  RnsPathEntry? pathFor(Uint8List destHash) => _pathMirror[_hex(destHash)];
  bool hasPath(Uint8List destHash) => _pathMirror.containsKey(_hex(destHash));
  int get pathCount => _pathMirror.length;

  Uint8List? nextHopForIdentity(RnsIdentity identity) {
    final want = _hex(identity.hash);
    for (final e in _pathMirror.values) {
      if (_hex(e.identity.hash) == want) return e.nextHop;
    }
    return null;
  }

  int nextHopInterfaceHwMtu(Uint8List destHash) {
    final path = pathFor(destHash);
    if (path == null) return kRnsMtu;
    return _ifaces[path.via]?.hardwareMtu ?? kRnsMtu;
  }

  int hwMtuForVia(String via) => _ifaces[via]?.hardwareMtu ?? kRnsMtu;

  int speedRankOf(String label) => _ifaces[label]?.speedRank ?? 2;

  /// Diagnostic mirror of [RnsTransport.pathInfo].
  Map<String, dynamic>? pathInfo(Uint8List destHash) {
    final e = _pathMirror[_hex(destHash)];
    if (e == null) return null;
    return {
      'nextHop': e.nextHop == null ? null : _hex(e.nextHop!),
      'via': e.via,
      'hops': e.hops,
      'ageMs': DateTime.now().millisecondsSinceEpoch - e.updatedMs,
      'identity': _hex(e.identity.hash),
    };
  }

  /// Labels of the owner-registered interfaces.
  List<String> get interfaceLabels => _ifaces.keys.toList(growable: false);

  static String _hex(List<int> b) =>
      b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
}

// ── engine isolate ───────────────────────────────────────────────────────────

/// Engine-side stand-in for an owner-held interface: send() bounces the frame
/// back to the owner, which dispatches it to the real socket/radio.
class _ExtIface implements RnsInterface {
  _ExtIface({
    required this.label,
    required this.speedRank,
    required this.hardwareMtu,
    required this.edge,
    required this.announceOnly,
    required SendPort toMain,
  }) : _toMain = toMain;

  @override
  final String label;
  @override
  final int speedRank;
  @override
  final int hardwareMtu;
  @override
  final bool edge;
  @override
  final bool announceOnly;
  final SendPort _toMain;

  @override
  void send(Uint8List packetRaw) => _toMain.send(['tx', label, packetRaw]);
}

// Guard the isolate: an unhandled async error is fatal by default, and a dead
// transport isolate means routing stops with nothing but a stack trace on
// stderr. dart:io raises exactly this class of error on its own — a socket
// torn down while a read event is already queued throws from a dart:io timer,
// outside any stream we listen to. Log it and keep routing.
Future<void> _engineMain(SendPort toMain) async {
  runZonedGuarded(
    () => _engineBody(toMain),
    (e, st) => toMain.send(['log', 'RNS/engine: unhandled $e']),
  );
}

Future<void> _engineBody(SendPort toMain) async {
  final transport = RnsTransport(
    log: (m) => toMain.send(['log', 'RNS/engine: $m']),
  );
  transport.onPathRequest =
      (wanted) => toMain.send(['pathreq', Uint8List.fromList(wanted)]);
  final ifaces = <String, _ExtIface>{};
  var lastSweepMs = 0;

  void pushPath(RnsPathEntry e) {
    toMain.send([
      'path',
      e.destHash,
      e.publicKey,
      e.appData,
      e.hops,
      e.via,
      e.nextHop,
      e.updatedMs,
    ]);
  }

  // Stats + changed-path sweep. The 2s cadence keeps the client mirror fresh
  // for sibling-path upgrades that don't ride an accepted announce.
  Timer.periodic(const Duration(seconds: 2), (_) {
    toMain.send([
      'stats',
      transport.passive,
      transport.announceRatePerSec,
      transport.pathCount,
    ]);
    final since = lastSweepMs;
    lastSweepMs = DateTime.now().millisecondsSinceEpoch;
    var pushed = 0;
    for (final e in transport.pathsView) {
      if (e.updatedMs >= since) {
        pushPath(e);
        if (++pushed >= 256) break; // bound one sweep's port traffic
      }
    }
  });

  final inbox = ReceivePort();
  toMain.send(inbox.sendPort);
  await for (final msg in inbox) {
    if (msg is! List || msg.isEmpty) continue;
    try {
      switch (msg[0] as String) {
        case 'ifaceAdd':
          final iface = _ExtIface(
            label: msg[1] as String,
            speedRank: msg[2] as int,
            hardwareMtu: msg[3] as int,
            edge: msg[4] as bool,
            announceOnly: msg[5] as bool,
            toMain: toMain,
          );
          ifaces[iface.label] = iface;
          transport.addInterface(iface);
        case 'ifaceRemove':
          final iface = ifaces.remove(msg[1] as String);
          if (iface != null) transport.removeInterface(iface);
        case 'ingest':
          final raw = msg[1] as Uint8List;
          final via = msg[2] as String;
          final p = RnsPacket.parse(raw);
          if (p == null) break;
          final ann = await transport.ingest(p, via);
          if (ann != null) {
            toMain.send([
              'ann',
              ann.destHash,
              ann.publicKey,
              ann.nameHash,
              ann.appData,
              ann.ratchet,
              p.hops,
              via,
            ]);
            final e = transport.pathFor(ann.destHash);
            if (e != null) pushPath(e);
          }
        case 'sendOnAll':
          transport.sendOnAll(msg[1] as Uint8List);
        case 'sendLinkAware':
          transport.sendLinkAware(msg[1] as Uint8List);
        case 'noteLinkIface':
          transport.noteLinkIface(msg[1] as Uint8List, msg[2] as String);
        case 'requestPath':
          transport.requestPath(msg[1] as Uint8List,
              force: msg.length > 2 && msg[2] == true);
        case 'pathFailed':
          transport.pathFailed(msg[1] as Uint8List,
              reason: msg[2] as String);
        case 'sendDataTo':
          transport.sendDataTo(msg[1] as Uint8List, msg[2] as Uint8List,
              context: msg[3] as int);
        case 'sendPlainTo':
          transport.sendPlainTo(msg[1] as Uint8List, msg[2] as Uint8List,
              context: msg[3] as int);
        case 'setPassive':
          transport.setPassive(msg[1] as bool, auto: msg[2] as bool);
        case 'transportId':
          transport.transportId = msg[1] as Uint8List?;
        case 'edgeBridge':
          transport.edgeBridge = msg[1] as bool;
        case 'priorityNames':
          transport.priorityAnnounceNames
            ..clear()
            ..addAll((msg[1] as List).cast<String>());
      }
    } catch (e) {
      toMain.send(['log', 'RNS/engine: cmd error: $e']);
    }
  }
}
