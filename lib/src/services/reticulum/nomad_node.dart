/*
 * NomadNode — fetch pages from NomadNet nodes over Reticulum.
 *
 * NomadNet nodes announce a destination on app "nomadnetwork", aspect "node",
 * and register page paths as RNS Link Request handlers ("/page/index.mu", …).
 * To read a page we open an initiator Link to the node, complete the ECDH
 * handshake, then send an RNS REQUEST for the path; the node answers with the
 * page bytes (micron markup) — inline for small pages, or via a Resource for
 * large ones. Dynamic pages (e.g. a chatroom) take input via `field_*`/`var_*`
 * variables carried in the request data.
 *
 * Transport-agnostic: the owner supplies a [send] callback + path helpers and
 * feeds inbound packets to [handlePacket] (returns true if consumed).
 */
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'rns_crypto.dart';
import 'rns_identity.dart';
import 'rns_link.dart';
import 'rns_packet.dart';
import 'rns_resource_receiver.dart';
import 'lxmf/lxmf_msgpack.dart';

const String kNomadApp = 'nomadnetwork';
const List<String> kNomadAspects = ['node'];

class _PageEntry {
  final RnsLink link;
  final Uint8List packedRequest; // sent once the link handshake completes
  final Completer<Uint8List?> done;
  RnsResourceReceiver? rx; // set if the response rides a Resource
  Timer? timeout;
  _PageEntry(this.link, this.packedRequest, this.done);
}

class NomadNode {
  final RnsIdentity identity;
  final void Function(Uint8List raw) send;
  final Uint8List? Function(RnsIdentity peer)? nextHopFor;
  final Uint8List? Function(Uint8List destHash)? nextHopForDest;
  final bool Function(Uint8List destHash)? hasPathForDest;
  final void Function(Uint8List destHash)? requestPath;
  final int Function(Uint8List destHash)? nextHopMtuForDest;
  final void Function(String msg)? log;

  final Map<String, _PageEntry> _fetch = {};

  NomadNode({
    required this.identity,
    required this.send,
    this.nextHopFor,
    this.nextHopForDest,
    this.hasPathForDest,
    this.requestPath,
    this.nextHopMtuForDest,
    this.log,
  });

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  /// Fetch [path] (e.g. "/page/index.mu") from the NomadNet node whose public
  /// identity is [nodeIdentity] (learned from its nomadnetwork.node announce).
  /// [fields] carries dynamic-page input variables (field_*/var_*), or null for
  /// a plain GET. Returns the raw page bytes (micron), or null on failure.
  Future<Uint8List?> fetchPage(
    RnsIdentity nodeIdentity,
    String path, {
    Map<String, Object?>? fields,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    final link = await RnsLink.initiator(nodeIdentity, kNomadApp, kNomadAspects);
    link.nextHop = await RnsLink.ensurePath(
        nodeIdentity, kNomadApp, kNomadAspects,
        nextHopFor: nextHopFor,
        nextHopForDest: nextHopForDest,
        hasPathForDest: hasPathForDest,
        requestPath: requestPath,
        maxPolls: 30);
    link.offerMtu(nextHopMtuForDest?.call(link.destHash) ?? kRnsMtu);
    // RNS request wire format: msgpack([time_seconds, path_hash(16), data]).
    final pathHash = RnsCrypto.truncatedHash(utf8.encode(path));
    final packed = msgpackEncode(
        [DateTime.now().millisecondsSinceEpoch / 1000.0, pathHash, fields]);
    // buildRequest() assigns the link id; must run before we key _fetch on it.
    final req = link.buildRequest();
    final entry = _PageEntry(link, packed, Completer<Uint8List?>());
    final id = _hex(link.linkId!);
    _fetch[id] = entry;
    entry.timeout = Timer(timeout, () {
      if (!entry.done.isCompleted) {
        log?.call('nomad: page fetch timeout $path');
        entry.done.complete(null);
      }
    });
    log?.call('nomad: opening link to ${_hex(link.destHash)} for $path');
    send(req.pack());
    final res = await entry.done.future;
    entry.timeout?.cancel();
    _fetch.remove(id);
    return res;
  }

  /// Feed an inbound packet. Returns true if it belonged to a page fetch.
  Future<bool> handlePacket(RnsPacket p, {int arrivalHwMtu = kRnsMtu}) async {
    if (p.destType != RnsDestType.link) return false;
    final e = _fetch[_hex(p.destHash)];
    if (e == null) return false;
    await _onPacket(e, p);
    return true;
  }

  Future<void> _onPacket(_PageEntry e, RnsPacket p) async {
    // Handshake phase: validate the node's proof, send LRRTT, then the REQUEST.
    if (e.link.status != RnsLinkStatus.active) {
      if (p.packetType == RnsPacketType.proof &&
          p.context == RnsContext.lrproof) {
        if (e.link.status != RnsLinkStatus.pending) return; // dup proof
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          log?.call('nomad: proof validation failed');
          _finish(e, null);
          return;
        }
        send(rtt.pack());
        // Link is active — send the page request over it.
        send(e.link
            .encrypt(e.packedRequest, context: RnsContext.request)
            .pack());
        log?.call('nomad: link active, request sent');
      }
      return;
    }
    // Active link: an inline RESPONSE, or a Resource carrying the response.
    if (p.context == RnsContext.response) {
      _finishWithPacked(e, e.link.decrypt(p));
      return;
    }
    if (p.context == RnsContext.resource ||
        p.context == RnsContext.resourceAdv ||
        p.context == RnsContext.resourceHmu) {
      final rx = e.rx ??= RnsResourceReceiver(e.link);
      for (final out in rx.handle(p)) {
        send(out.pack());
      }
      if (rx.complete && rx.payload != null) {
        _finishWithPacked(e, rx.payload!);
      }
    }
  }

  // The response is msgpack([request_id, response_data]); pull response_data.
  void _finishWithPacked(_PageEntry e, Uint8List packed) {
    try {
      final unpacked = msgpackDecode(packed);
      if (unpacked is List && unpacked.length >= 2) {
        final resp = unpacked[1];
        if (resp is Uint8List) {
          _finish(e, resp);
          return;
        }
        if (resp is List<int>) {
          _finish(e, Uint8List.fromList(resp));
          return;
        }
        if (resp is String) {
          _finish(e, Uint8List.fromList(utf8.encode(resp)));
          return;
        }
      }
      log?.call('nomad: unexpected response shape');
      _finish(e, null);
    } catch (err) {
      log?.call('nomad: response decode failed: $err');
      _finish(e, null);
    }
  }

  void _finish(_PageEntry e, Uint8List? bytes) {
    if (!e.done.isCompleted) e.done.complete(bytes);
  }
}
