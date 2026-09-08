/*
 * A transport node answers path requests for destinations it merely KNOWS, not
 * only for its own — the behaviour that makes an always-on station useful to
 * the ones attached to it. Reticulum routes on announce-derived hop memory, so
 * the answer is the destination's ORIGINAL announce replayed with the answerer's
 * transport id; a station that never heard that announce can then address the
 * destination through the answerer. A leaf answers for nobody.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _FakeIface extends RnsInterface {
  _FakeIface(this._label);
  final String _label;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

/// The wire form a station uses to ask "who has [dest]" (dest 16B + the asker's
/// transport id 16B + a random tag), addressed to the well-known plain
/// path-request destination.
Uint8List _pathRequest(Uint8List dest, Uint8List askerTransportId) {
  final b = BytesBuilder()
    ..add(dest)
    ..add(askerTransportId)
    ..add(Uint8List(16));
  // The dest hash of the request itself is derived by the transport; reuse its
  // own builder by asking a throwaway transport to emit one, then swap in our
  // payload — keeps the test honest about the real destination hash.
  final probeIface = _FakeIface('probe');
  final probe = RnsTransport()..addInterface(probeIface);
  probe.requestPath(dest);
  final emitted = RnsPacket.parse(probeIface.sent.single)!;
  return RnsPacket(
    destHash: emitted.destHash,
    data: b.toBytes(),
    headerType: RnsHeaderType.header1,
    transportType: RnsTransportType.broadcast,
    destType: RnsDestType.plain,
    packetType: RnsPacketType.data,
    context: RnsContext.none,
  ).pack();
}

void main() {
  test('a transport node answers for a destination it holds a path to',
      () async {
    final hub = Uint8List(16)..[0] = 0xAB;
    final up = _FakeIface('tcp'); // where the hub learned X
    final lan = _FakeIface('lan'); // where the asker lives
    final t = RnsTransport(transportId: hub)
      ..addInterface(up)
      ..addInterface(lan);

    // X announces itself somewhere upstream; the hub learns the path.
    final x = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(x, 'pathanswer', const ['x']);
    expect(await t.ingest(ann, 'tcp'), isNotNull);
    up.sent.clear();
    lan.sent.clear();

    // A station on the LAN, which never heard X, asks who has it.
    final asked = RnsPacket.parse(_pathRequest(ann.destHash, Uint8List(16)))!;
    await t.ingest(asked, 'lan');

    expect(lan.sent.length, 1, reason: 'answered on the asking interface');
    final reply = RnsPacket.parse(lan.sent.single)!;
    expect(reply.packetType, RnsPacketType.announce);
    expect(reply.context, RnsContext.pathResponse);
    expect(reply.destHash, ann.destHash);
    expect(reply.headerType, RnsHeaderType.header2,
        reason: 'tagged so the asker routes THROUGH us');
    expect(reply.transportId, hub);
    expect(t.pathAnswersServed, 1);

    // The asker really learns a usable path from that answer.
    final askerIface = _FakeIface('lan');
    final asker = RnsTransport()..addInterface(askerIface);
    expect(await asker.ingest(reply, 'lan'), isNotNull);
    final learned = asker.pathFor(ann.destHash);
    expect(learned, isNotNull, reason: 'X is now reachable for a node that '
        'never heard X announce');
    expect(learned!.nextHop, hub, reason: 'and reachable THROUGH the hub');
  });

  test('a leaf answers for nobody, and keeps no announce bytes to do it with',
      () async {
    final up = _FakeIface('tcp');
    final lan = _FakeIface('lan');
    final leaf = RnsTransport() // no transportId: not a transport node
      ..addInterface(up)
      ..addInterface(lan);

    final x = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(x, 'pathanswer', const ['x']);
    expect(await leaf.ingest(ann, 'tcp'), isNotNull);
    expect(leaf.pathFor(ann.destHash)!.announceData, isNull,
        reason: 'a leaf pays no memory for a job it never does');
    up.sent.clear();
    lan.sent.clear();

    final asked = RnsPacket.parse(_pathRequest(ann.destHash, Uint8List(16)))!;
    await leaf.ingest(asked, 'lan');
    expect(lan.sent, isEmpty);
    expect(leaf.pathAnswersServed, 0);
  });

  test('never answered back onto the interface the path itself came from',
      () async {
    final up = _FakeIface('tcp');
    final t = RnsTransport(transportId: Uint8List(16)..[0] = 0xCD)
      ..addInterface(up);

    final x = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(x, 'pathanswer', const ['x']);
    await t.ingest(ann, 'tcp');
    up.sent.clear();

    final asked = RnsPacket.parse(_pathRequest(ann.destHash, Uint8List(16)))!;
    await t.ingest(asked, 'tcp'); // asked on the same side we learned it
    expect(up.sent, isEmpty,
        reason: 'the asker is on the side that taught us — it would learn '
            'nothing and we would loop');
  });
}
