/*
 * Requests and responses over a Reticulum link (RNS Link.request /
 * Destination.register_request_handler), both sides.
 *
 * [RnsRequestServer] answers on one destination: it accepts links to it, and
 * on each link answers REQUEST packets by the path they name. [RnsRequestClient]
 * opens one link to such a destination and sends any number of requests over
 * it, matching responses by request id.
 *
 * Wire (RNS 1.x): a request is msgpack([time_s, path_hash(16), data]) in a
 * packet of context REQUEST, or the payload of a Resource when it does not fit
 * one packet. Its id is the truncated hash of that packed request. A response
 * is msgpack([request_id, data]) in a RESPONSE packet, or a Resource. One
 * Resource travels each way at a time on a link; the rest wait their turn.
 *
 * Transport-agnostic like the other nodes: the owner supplies [send] and feeds
 * inbound packets to handlePacket (true when consumed).
 */
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'lxmf/lxmf_msgpack.dart';
import 'rns_crypto.dart';
import 'rns_identity.dart';
import 'rns_link.dart';
import 'rns_packet.dart';
import 'rns_resource.dart';
import 'rns_resource_receiver.dart';

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// The largest request or response sent as one packet; past it, a Resource.
const int kRnsRequestInlineMax = 380;

/// A request handler: the request's data (decoded msgpack: bytes, a map, a
/// string or null) and the link it came on; the response data, or null for none.
typedef RnsRequestHandler = Future<Object?> Function(Object? data, RnsLink link);

/// Both directions of one link: single packets, and one Resource at a time
/// each way, the next waiting in [_queue].
class _LinkPipe {
  _LinkPipe(this.link, this.send, this.onPayload);
  final RnsLink link;
  final void Function(Uint8List raw) send;
  /// A whole inbound payload: from a packet of [context], or a Resource (-1).
  final void Function(Uint8List payload, int context) onPayload;
  RnsResourceSender? _tx;
  RnsResourceReceiver? _rx;
  final List<Uint8List> _queue = [];
  int lastMs = DateTime.now().millisecondsSinceEpoch;

  void sendPayload(Uint8List payload, int context) {
    if (payload.length <= kRnsRequestInlineMax) {
      send(link.encrypt(payload, context: context).pack());
      return;
    }
    if (_tx != null) {
      _queue.add(payload);
      return;
    }
    _startTx(payload);
  }

  void _startTx(Uint8List payload) {
    final s = RnsResourceSender(link, payload)..prepare();
    _tx = s;
    send(s.advertisementPacket().pack());
  }

  void handle(RnsPacket p) {
    lastMs = DateTime.now().millisecondsSinceEpoch;
    switch (p.context) {
      case RnsContext.resourceReq:
        final tx = _tx;
        if (tx != null) {
          for (final part in tx.handleRequest(link.decrypt(p))) {
            send(part.pack());
          }
        }
        break;
      case RnsContext.resourcePrf:
        final tx = _tx;
        if (tx != null && tx.validateProof(p.data)) {
          if (!tx.complete) {
            send(tx.advertisementPacket().pack());
          } else {
            _tx = null;
            if (_queue.isNotEmpty) _startTx(_queue.removeAt(0));
          }
        }
        break;
      case RnsContext.resourceAdv:
      case RnsContext.resourceHmu:
      case RnsContext.resource:
        final rx = _rx ??= RnsResourceReceiver(link);
        for (final out in rx.handle(p)) {
          send(out.pack());
        }
        if (rx.complete) {
          _rx = null;
          final body = rx.payload;
          if (body != null) onPayload(body, -1);
        } else if (rx.error != null) {
          _rx = null;
        }
        break;
      case RnsContext.request:
      case RnsContext.response:
        onPayload(link.decrypt(p), p.context);
        break;
      default:
        break;
    }
  }
}

/// Answers requests on [destHash] (one of [identity]'s destinations).
class RnsRequestServer {
  RnsRequestServer({
    required this.identity,
    required this.destHash,
    required this.send,
    this.maxLinks = 16,
    this.idle = const Duration(minutes: 10),
    this.log,
  });

  final RnsIdentity identity;
  final Uint8List destHash;
  final void Function(Uint8List raw) send;
  final int maxLinks;
  final Duration idle;
  final void Function(String msg)? log;

  final Map<String, RnsRequestHandler> _handlers = {};
  final Map<String, _ServerLink> _links = {};

  /// Answer requests for [path] with [handler].
  void register(String path, RnsRequestHandler handler) {
    _handlers[_hex(RnsCrypto.truncatedHash(utf8.encode(path)))] = handler;
  }

  int get openLinks => _links.length;

  Future<bool> handlePacket(RnsPacket p, {int arrivalHwMtu = kRnsMtu}) async {
    if (p.packetType == RnsPacketType.linkRequest &&
        RnsCrypto.constantTimeEquals(p.destHash, destHash)) {
      await _accept(p, arrivalHwMtu);
      return true;
    }
    if (p.destType != RnsDestType.link) return false;
    final s = _links[_hex(p.destHash)];
    if (s == null) return false;
    if (s.link.status != RnsLinkStatus.active) {
      if (p.context == RnsContext.lrrtt) s.link.handleRtt(p);
      return true;
    }
    if (p.context == RnsContext.linkClose) {
      _links.remove(_hex(p.destHash));
      return true;
    }
    if (p.context == RnsContext.keepalive) {
      s.pipe.lastMs = DateTime.now().millisecondsSinceEpoch;
      return true;
    }
    s.pipe.handle(p);
    return true;
  }

  Future<void> _accept(RnsPacket request, int arrivalHwMtu) async {
    final id = _hex(RnsLink.linkIdFromRequest(request));
    final known = _links[id];
    if (known != null) {
      // The same LINKREQUEST on another interface: the cached proof, no new crypto.
      final proof = known.proof;
      if (proof != null) send(proof);
      return;
    }
    _sweep();
    if (_links.length >= maxLinks) {
      log?.call('requests: link refused, $maxLinks open');
      return;
    }
    try {
      final link = await RnsLink.responder(identity, request, arrivalHwMtu: arrivalHwMtu);
      final s = _ServerLink(link);
      s.pipe = _LinkPipe(link, send, (payload, ctx) => _onRequest(s, payload));
      _links[id] = s;
      final proof = (await link.buildProof()).pack();
      s.proof = proof;
      send(proof);
    } catch (e) {
      log?.call('requests: accept failed: $e');
    }
  }

  void _sweep() {
    final now = DateTime.now().millisecondsSinceEpoch;
    _links.removeWhere((_, s) => now - s.pipe.lastMs > idle.inMilliseconds);
  }

  Future<void> _onRequest(_ServerLink s, Uint8List packed) async {
    Object? decoded;
    try {
      decoded = msgpackDecode(packed);
    } catch (_) {
      return;
    }
    if (decoded is! List || decoded.length < 3) return;
    final pathHash = decoded[1];
    if (pathHash is! List<int>) return;
    final handler = _handlers[_hex(Uint8List.fromList(pathHash))];
    final rid = RnsCrypto.truncatedHash(packed);
    if (handler == null) {
      log?.call('requests: no handler for a path');
      return;
    }
    Object? answer;
    try {
      answer = await handler(decoded[2], s.link);
    } catch (e) {
      log?.call('requests: handler failed: $e');
      return;
    }
    s.pipe.sendPayload(msgpackEncode([rid, answer]), RnsContext.response);
  }
}

class _ServerLink {
  _ServerLink(this.link);
  final RnsLink link;
  late _LinkPipe pipe;
  Uint8List? proof;
}

/// One link to a request server, any number of requests over it.
class RnsRequestClient {
  RnsRequestClient({
    required this.peer,
    required this.appName,
    required this.aspects,
    required this.send,
    this.nextHopForDest,
    this.hasPathForDest,
    this.requestPath,
    this.nextHopMtuForDest,
    this.log,
  });

  final RnsIdentity peer;
  final String appName;
  final List<String> aspects;
  final void Function(Uint8List raw) send;
  final Uint8List? Function(Uint8List destHash)? nextHopForDest;
  final bool Function(Uint8List destHash)? hasPathForDest;
  final void Function(Uint8List destHash)? requestPath;
  final int Function(Uint8List destHash)? nextHopMtuForDest;
  final void Function(String msg)? log;

  RnsLink? _link;
  _LinkPipe? _pipe;
  Completer<bool>? _open;
  final Map<String, Completer<Object?>> _pending = {};
  Timer? _keepalive;

  bool get isOpen => _link?.status == RnsLinkStatus.active;
  Uint8List? get linkId => _link?.linkId;

  /// Open the link: find a path, handshake. True when it is up.
  Future<bool> open({Duration timeout = const Duration(seconds: 30)}) async {
    if (isOpen) return true;
    if (_open != null) return _open!.future;
    final done = _open = Completer<bool>();
    try {
      final link = await RnsLink.initiatorWithPath(peer, appName, aspects,
          nextHopForDest: nextHopForDest,
          hasPathForDest: hasPathForDest,
          requestPath: requestPath,
          nextHopMtuForDest: nextHopMtuForDest,
          maxPolls: 60);
      _link = link;
      _pipe = _LinkPipe(link, send, _onResponse);
      send(link.buildRequest().pack());
    } catch (e) {
      log?.call('requests: open failed: $e');
      _open = null;
      return false;
    }
    final t = Timer(timeout, () {
      if (!done.isCompleted) done.complete(false);
    });
    final ok = await done.future;
    t.cancel();
    _open = null;
    if (ok) {
      _keepalive = Timer.periodic(const Duration(minutes: 2), (_) {
        final l = _link;
        if (l != null && isOpen) {
          send(l.encrypt(Uint8List.fromList([0xFF]), context: RnsContext.keepalive).pack());
        }
      });
    }
    return ok;
  }

  /// Send a request for [path] with [data]; its response data, or null on a
  /// timeout or a closed link.
  Future<Object?> request(String path, Object? data,
      {Duration timeout = const Duration(seconds: 60)}) async {
    if (!isOpen && !await open()) return null;
    final packed = msgpackEncode([
      DateTime.now().millisecondsSinceEpoch / 1000.0,
      RnsCrypto.truncatedHash(utf8.encode(path)),
      data,
    ]);
    final rid = _hex(RnsCrypto.truncatedHash(packed));
    final c = Completer<Object?>();
    _pending[rid] = c;
    _pipe!.sendPayload(packed, RnsContext.request);
    final t = Timer(timeout, () {
      if (!c.isCompleted) c.complete(null);
    });
    final r = await c.future;
    t.cancel();
    _pending.remove(rid);
    return r;
  }

  Future<bool> handlePacket(RnsPacket p) async {
    final l = _link;
    if (l == null || p.destType != RnsDestType.link) return false;
    if (l.linkId == null || !RnsCrypto.constantTimeEquals(p.destHash, l.linkId!)) {
      return false;
    }
    if (l.status != RnsLinkStatus.active) {
      if (p.packetType == RnsPacketType.proof && p.context == RnsContext.lrproof) {
        final rtt = await l.handleProof(p);
        if (rtt != null) {
          send(rtt.pack());
          final o = _open;
          if (o != null && !o.isCompleted) o.complete(true);
        }
      }
      return true;
    }
    if (p.context == RnsContext.linkClose) {
      close(notify: false);
      return true;
    }
    _pipe?.handle(p);
    return true;
  }

  void _onResponse(Uint8List packed, int context) {
    Object? d;
    try {
      d = msgpackDecode(packed);
    } catch (_) {
      return;
    }
    if (d is! List || d.length < 2 || d[0] is! List<int>) return;
    final c = _pending[_hex(Uint8List.fromList(d[0] as List<int>))];
    if (c != null && !c.isCompleted) c.complete(d[1]);
  }

  void close({bool notify = true}) {
    _keepalive?.cancel();
    final l = _link;
    if (notify && l != null && isOpen) {
      send(l.encrypt(Uint8List.fromList(l.linkId!), context: RnsContext.linkClose).pack());
    }
    _link = null;
    _pipe = null;
    for (final c in _pending.values) {
      if (!c.isCompleted) c.complete(null);
    }
    _pending.clear();
  }
}
