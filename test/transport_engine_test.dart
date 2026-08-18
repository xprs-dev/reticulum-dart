/*
 * RnsTransportClient / engine-isolate round trip: an inbound announce ingested
 * through the client is validated IN THE ENGINE ISOLATE, comes back as an
 * onAnnounce event, populates the client's path mirror, and (transport-node
 * mode) is rebroadcast out of the OTHER registered interface via a tx event.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _FakeIface implements RnsInterface {
  _FakeIface(this.label);
  final List<Uint8List> sent = [];
  @override
  final String label;
  @override
  final int speedRank = 2;
  @override
  int get hardwareMtu => kRnsMtu;
  @override
  bool get edge => false;
  @override
  bool get announceOnly => false;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

Future<Uint8List> _rawAnnounce() async {
  final id = await RnsIdentity.generate();
  final p = await RnsAnnounceBuilder.build(id, 'enginetest', const ['peer']);
  return p.pack();
}

void main() {
  test('engine ingest → announce event + path mirror + rebroadcast', () async {
    final client = await RnsTransportClient.spawn();
    addTearDown(client.close);

    final a = _FakeIface('tcp:a');
    final b = _FakeIface('tcp:b');
    client
      ..transportId = Uint8List(16) // transport node → rebroadcasts
      ..addInterface(a)
      ..addInterface(b);

    RnsAnnounce? got;
    var hops = -1;
    var via = '';
    client.onAnnounce = (ann, h, v) {
      got = ann;
      hops = h;
      via = v;
    };

    final raw = await _rawAnnounce();
    client.ingestRaw(raw, 'tcp:a');

    // Announce validation crosses two isolates + the crypto worker: poll.
    for (var i = 0; i < 100 && got == null; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(got, isNotNull, reason: 'validated announce comes back');
    expect(hops, 0);
    expect(via, 'tcp:a');

    // Path mirror upsert accompanied the announce.
    expect(client.hasPath(got!.destHash), isTrue);
    expect(client.pathFor(got!.destHash)!.via, 'tcp:a');
    expect(client.nextHopForIdentity(got!.identity), isNull,
        reason: 'direct neighbour — no transport next hop');

    // Rebroadcast went out the OTHER interface only.
    for (var i = 0; i < 100 && b.sent.isEmpty; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(b.sent, isNotEmpty, reason: 'transport node relays to tcp:b');
    expect(a.sent, isEmpty, reason: 'never relayed back where it came from');

    // sendOnAll round-trips to both interfaces.
    client.sendOnAll(raw);
    for (var i = 0; i < 100 && a.sent.isEmpty; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(a.sent, isNotEmpty);
  });
}
