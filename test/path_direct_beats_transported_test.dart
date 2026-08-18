/*
 * Path selection: a neighbour you hear YOURSELF wins over one reached through
 * somebody else, whatever medium each arrived on.
 *
 * Speed rank alone put a phone with no internet — sitting a metre away,
 * announcing itself over Bluetooth — behind an internet hub, because tcp
 * outranks ble. The hub could not reach it (it has no internet), so every
 * message timed out: "unreachable after 7 tries — left for relay pickup",
 * while the device was in the room the whole time. Speed decides between paths
 * of equal directness; it must not decide between "arrives" and "does not".
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Iface extends RnsInterface {
  _Iface(this._label, this._rank);
  final String _label;
  final int _rank;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  int get speedRank => _rank;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

const int _rankBle = 1;
const int _rankTcp = 2;

Future<RnsPacket> _announce(RnsIdentity id) =>
    RnsAnnounceBuilder.build(id, 'pathtest', const ['peer']);

/// The same announce as it looks after a hub relayed it: one hop further, and
/// carrying the relay's transport id.
RnsPacket _transported(RnsPacket p) => RnsPacket(
      headerType: RnsHeaderType.header2,
      packetType: p.packetType,
      destHash: p.destHash,
      context: p.context,
      data: p.data,
      transportId: Uint8List(16),
      hops: p.hops + 1,
      destType: p.destType,
    );

void main() {
  group('direct beats transported', () {
    test('a Bluetooth neighbour replaces a path learned through a hub',
        () async {
      final tcp = _Iface('tcp', _rankTcp);
      final ble = _Iface('ble5', _rankBle);
      final t = RnsTransport(transportId: Uint8List(16))
        ..addInterface(tcp)
        ..addInterface(ble);

      final id = await RnsIdentity.generate();
      final ann = await _announce(id);

      // First: the hub tells us about the peer.
      await t.ingest(_transported(ann), 'tcp');
      expect(t.pathFor(ann.destHash)?.via, 'tcp');

      // Then we hear the peer ourselves, over Bluetooth.
      await t.ingest(ann, 'ble5');
      expect(t.pathFor(ann.destHash)?.via, 'ble5',
          reason: 'the peer is our own neighbour — the hub cannot reach it');
      expect(t.pathFor(ann.destHash)?.hops, 1,
          reason: 'one hop: straight from the peer to us');
    });

    test('a hub route does NOT displace a neighbour we hear directly',
        () async {
      final tcp = _Iface('tcp', _rankTcp);
      final ble = _Iface('ble5', _rankBle);
      final t = RnsTransport(transportId: Uint8List(16))
        ..addInterface(tcp)
        ..addInterface(ble);

      final id = await RnsIdentity.generate();
      final ann = await _announce(id);

      await t.ingest(ann, 'ble5');
      expect(t.pathFor(ann.destHash)?.via, 'ble5');

      // The same announce comes back around through a hub — faster medium, but
      // one hop further. Directness wins.
      await t.ingest(_transported(ann), 'tcp');
      expect(t.pathFor(ann.destHash)?.via, 'ble5',
          reason: 'a relayed copy must not shadow the peer we hear ourselves');
    });

    // Among paths of the SAME directness, the faster medium still wins — that
    // rule was right and stays.
    test('between two direct paths the faster medium still wins', () async {
      final lan = _Iface('lan', 3);
      final ble = _Iface('ble5', _rankBle);
      final t = RnsTransport(transportId: Uint8List(16))
        ..addInterface(lan)
        ..addInterface(ble);

      final id = await RnsIdentity.generate();
      final ann = await _announce(id);

      await t.ingest(ann, 'ble5');
      expect(t.pathFor(ann.destHash)?.via, 'ble5');
      await t.ingest(ann, 'lan');
      expect(t.pathFor(ann.destHash)?.via, 'lan');
    });
  });
}
