/*
 * A peer that LEAVES the LAN must stay reachable over the hub.
 *
 * The transport pins an identity to the fastest medium it has been heard on, so
 * that a co-located peer is reached over the LAN even when the broadcast
 * announce for one specific destination was lost. The pin is a claim about
 * where a peer *is* — and a peer can move.
 *
 * The bug this locks: the pin was permanent. A phone that left the LAN (moved to
 * cellular / another AP) kept having every hub-heard announce rewritten back to
 * `via: lan, hops: 1`, aiming every packet we sent it at a LAN it had left. It
 * never self-healed, because the same-capability rank rule refuses to replace a
 * faster-ranked (LAN) path with a slower-ranked (hub) one — so the dead path
 * outranked the live one forever, and the peer was unreachable until restart.
 * Observed live: C61 could not reach TANK2 by ANY transport (link, LXMF, PLAIN)
 * after TANK2 moved to a hotspot.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Iface extends RnsInterface {
  _Iface(this._label, this._rank);
  final String _label;
  final int _rank;
  @override
  String get label => _label;
  @override
  int get speedRank => _rank;
  @override
  void send(Uint8List raw) {}
}

String _nh(String app) => _hex(RnsDestination.nameHash(app, const ['peer']));

String _hex(Uint8List b) =>
    [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

/// Two destinations of ONE identity — the pin is identity-level, so a second
/// dest is what proves the pin is being applied (and later, undone).
Future<(RnsIdentity, RnsPacket, RnsPacket)> _peer() async {
  final id = await RnsIdentity.generate();
  final a = await RnsAnnounceBuilder.build(id, 'relay', const ['peer']);
  final b = await RnsAnnounceBuilder.build(id, 'chat', const ['peer']);
  return (id, a, b);
}

/// A peer re-announces periodically, and each announce is a NEW packet (fresh
/// random hash). Re-sending the SAME packet object would be dropped by the
/// packet-hash dedup, so a test that reused one would silently exercise nothing.
Future<RnsPacket> _reannounce(RnsIdentity id, String app) =>
    RnsAnnounceBuilder.build(id, app, const ['peer']);

void main() {
  late _Iface lan;
  late _Iface hub;
  late RnsTransport t;

  setUp(() {
    lan = _Iface('lan', 3); // fast, direct
    hub = _Iface('tcp:hub', 2); // slower, but the only medium that still works
    t = RnsTransport(transportId: Uint8List(16))
      ..addInterface(lan)
      ..addInterface(hub)
      // Exempt from the new-destination flood budget (1 per 3 s), which would
      // otherwise shed our announces and quietly make these tests pass/fail for
      // the wrong reason. This is what a node does for its own overlay.
      ..priorityAnnounceNames.addAll({_nh('relay'), _nh('chat')});
  });

  test('while the peer IS on the LAN, a hub-heard announce is pinned to the LAN',
      () async {
    final (_, relayAnn, chatAnn) = await _peer();

    await t.ingest(relayAnn, 'lan'); // heard on the LAN: pin the identity
    await t.ingest(chatAnn, 'tcp:hub'); // this dest only heard via the hub

    final p = t.pathInfo(chatAnn.destHash)!;
    expect(p['via'], 'lan',
        reason: 'the co-located peer is reachable on the LAN — this is the '
            'optimisation, and it must keep working');
    expect(p['hops'], 1);
  });

  test('a peer that LEFT the LAN is demoted to the hub, and stays reachable',
      () async {
    final (id, relayAnn, chatAnn) = await _peer();

    // It was here, on the LAN.
    await t.ingest(relayAnn, 'lan');
    await t.ingest(chatAnn, 'lan');
    expect(t.pathInfo(relayAnn.destHash)!['via'], 'lan');

    // It leaves. From now on we only ever hear it via the hub. Each such
    // announce is a MISS against the pin.
    for (var i = 0; i < 6; i++) {
      await t.ingest(await _reannounce(id, 'relay'), 'tcp:hub');
    }

    for (final ann in [relayAnn, chatAnn]) {
      final p = t.pathInfo(ann.destHash)!;
      expect(p['via'], 'tcp:hub',
          reason: 'the LAN is dead for this peer; every path of the identity '
              'must fall back to the medium we can actually reach it on. A '
              'stale pin here is a silent black hole.');
    }
  });

  test('the demotion repoints paths, not just the pin', () async {
    // The subtle half of the bug: dropping the pin alone leaves the path
    // entries still saying `via: lan`, and the rank rule then refuses to
    // replace a fast (LAN) entry with a slow (hub) one — so the dead path
    // outranks the live one forever.
    final (id, relayAnn, chatAnn) = await _peer();
    await t.ingest(relayAnn, 'lan');
    await t.ingest(chatAnn, 'lan');

    // ONLY the relay dest keeps re-announcing (over the hub). The chat dest is
    // silent — as a rarely-announced dest really is.
    for (var i = 0; i < 6; i++) {
      await t.ingest(await _reannounce(id, 'relay'), 'tcp:hub');
    }

    expect(t.pathInfo(chatAnn.destHash)!['via'], 'tcp:hub',
        reason: 'a sibling dest that never re-announced must still be demoted '
            'with the identity, or it keeps black-holing');
  });

  test('a peer still on the LAN is NOT demoted by interleaved hub announces',
      () async {
    // The peer announces to the hub too, so we hear BOTH copies. That must not
    // be mistaken for the peer having left, or we would throw away the LAN
    // optimisation for every co-located peer.
    final (id, relayAnn, chatAnn) = await _peer();
    await t.ingest(relayAnn, 'lan');

    for (var i = 0; i < 10; i++) {
      await t.ingest(await _reannounce(id, 'relay'), 'tcp:hub'); // miss
      await t.ingest(await _reannounce(id, 'relay'), 'lan'); // still here: reset
    }

    await t.ingest(chatAnn, 'tcp:hub');
    expect(t.pathInfo(chatAnn.destHash)!['via'], 'lan',
        reason: 'still on the LAN — the pin must survive');
  });
}
