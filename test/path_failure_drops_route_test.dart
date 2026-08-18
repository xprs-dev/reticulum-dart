/*
 * A route that does not deliver must not survive the message it lost.
 *
 * Observed on two phones: one lost Wi-Fi and kept only Bluetooth. Its
 * neighbour, a metre away, had learned it through an internet hub while it was
 * still on Wi-Fi, and went on posting into that 5-hop route for fifty minutes —
 * "unreachable after 7 tries — left for relay pickup" — because the path table
 * only ever learned from announces, and the peer had no internet left to
 * announce over. Nothing in the system treated a failed delivery as evidence
 * about the route.
 *
 * So: a reported failure drops the entry (and the identity pin that would drag
 * the peer's other destinations back onto the same dead interface), and asks
 * the network again, which is what lets the radio the two of them still share
 * answer.
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

Future<RnsPacket> _announce(RnsIdentity id, String aspect) =>
    RnsAnnounceBuilder.build(id, 'pathtest', [aspect]);

/// Name hash of the destinations this test announces, in the form the
/// transport's priority set keeps them (hex).
String _nameHash() => _hex(RnsDestination.nameHash('pathtest', const ['delivery']));

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// The same announce as a hub relays it: one hop further, carrying the relay's
/// transport id, so it installs as a transported (next-hop) route.
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
  group('a failed delivery invalidates the route', () {
    late _Iface tcp;
    late _Iface ble;
    late RnsTransport t;
    late RnsIdentity peer;
    late RnsPacket delivery;
    late RnsPacket sibling;

    setUp(() async {
      tcp = _Iface('tcp:hub:4242', _rankTcp);
      ble = _Iface('ble5', _rankBle);
      t = RnsTransport(transportId: Uint8List(16))
        ..addInterface(tcp)
        ..addInterface(ble);
      // Exempt this test's overlay from the new-destination verify budget (1
      // per 3s), which otherwise sheds the second announce and the test would
      // be measuring the budget rather than the path logic.
      t.priorityAnnounceNames.add(_nameHash());
      peer = await RnsIdentity.generate();
      delivery = await _announce(peer, 'delivery');
      sibling = await _announce(peer, 'chat');
      // Learned through the hub, back when the peer had internet.
      await t.ingest(_transported(delivery), 'tcp:hub:4242');
      await t.ingest(_transported(sibling), 'tcp:hub:4242');
    });

    test('the dead entry is gone and a path request goes out', () async {
      expect(t.hasPath(delivery.destHash), isTrue);
      expect(t.pathFor(delivery.destHash)!.via, 'tcp:hub:4242');

      final bleBefore = ble.sent.length;
      final dropped = t.pathFailed(delivery.destHash, reason: 'test');

      expect(dropped, isTrue);
      expect(t.hasPath(delivery.destHash), isFalse,
          reason: 'the route we could not deliver on is forgotten');
      expect(ble.sent.length, greaterThan(bleBefore),
          reason: 'and we ask again, on every interface we have');
    });

    test('the peer\'s other destinations on that route go too', () async {
      // Otherwise the next message picks a sibling entry and posts into the
      // same hole: one peer, one dead interface, one decision.
      t.pathFailed(delivery.destHash);
      expect(t.hasPath(sibling.destHash), isFalse);
    });

    test('a route on a DIFFERENT interface is left alone', () async {
      final other = await RnsIdentity.generate();
      final otherAnn = await _announce(other, 'delivery');
      await t.ingest(otherAnn, 'ble5'); // direct neighbour, unrelated

      t.pathFailed(delivery.destHash);
      expect(t.hasPath(otherAnn.destHash), isTrue,
          reason: 'one peer failing says nothing about another');
    });

    test('the radio in the room can now install the route', () async {
      t.pathFailed(delivery.destHash);
      // The peer answers our path request over the bearer we still share.
      await t.ingest(delivery, 'ble5');

      final path = t.pathFor(delivery.destHash);
      expect(path, isNotNull);
      expect(path!.via, 'ble5',
          reason: 'the route that answers is the route we keep');
      expect(path.nextHop, isNull, reason: 'a neighbour needs no next hop');
    });

    test('a dest we hold no path for still asks, and says nothing was lost',
        () async {
      final unknown = Uint8List(16);
      final bleBefore = ble.sent.length;
      expect(t.pathFailed(unknown), isFalse);
      expect(ble.sent.length, greaterThan(bleBefore));
    });
  });
}
