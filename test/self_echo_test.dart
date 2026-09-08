/*
 * A path through ourselves is never a path. A transport node re-airs announces
 * tagged with its own transport id, and on a broadcast bearer that frame can
 * come back — reflected by the access point, or from an address the loopback
 * filter does not recognise. Learning from it installs a route whose next hop
 * is this very node, and everything addressed to that destination then goes
 * nowhere. Measured on a promoted phone: "via lan, 3 hops, next hop = itself",
 * 140 messages held for relay, none delivered.
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

void main() {
  test('our own rebroadcast, returning on a broadcast bearer, teaches nothing',
      () async {
    final me = Uint8List(16)..[0] = 0x99;
    final lan = _FakeIface('lan');
    final hub = _FakeIface('tcp');
    final t = RnsTransport(transportId: me)
      ..edgeQuiet = true
      ..addInterface(lan)
      ..addInterface(hub);

    // Somebody far away announces; we hear it on the hub and re-air it.
    final far = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(far, 'selfecho', const ['far']);
    expect(await t.ingest(ann, 'tcp'), isNotNull);
    expect(lan.sent.length, 1, reason: 'a promoted node re-airs onto the LAN');
    final viaHub = t.pathFor(ann.destHash)!.via;
    expect(viaHub, 'tcp');

    // That very frame comes back to us on the LAN.
    final echo = RnsPacket.parse(lan.sent.single)!;
    expect(echo.transportId, me, reason: 'it is tagged with our own id');
    await t.ingest(echo, 'lan');

    expect(t.pathFor(ann.destHash)!.via, 'tcp',
        reason: 'the real path must survive our own echo');
    expect(t.pathFor(ann.destHash)!.nextHop, isNot(me),
        reason: 'we must never route a destination through ourselves');
    expect(t.selfEchoDropped, greaterThan(0));
  });

  test('a genuine relay by ANOTHER transport node is still learned', () async {
    final me = Uint8List(16)..[0] = 0x99;
    final other = Uint8List(16)..[0] = 0x11;
    final lan = _FakeIface('lan');
    final t = RnsTransport(transportId: me)..addInterface(lan);

    final far = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(far, 'selfecho', const ['far']);
    final relayed = RnsPacket(
      destHash: ann.destHash,
      data: ann.data,
      packetType: RnsPacketType.announce,
      headerType: RnsHeaderType.header2,
      transportType: RnsTransportType.transport,
      transportId: other,
      hops: 1,
    );
    expect(await t.ingest(relayed, 'lan'), isNotNull);
    expect(t.pathFor(ann.destHash)!.nextHop, other);
    expect(t.selfEchoDropped, 0);
  });
}
