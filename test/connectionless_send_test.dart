/*
 * A connectionless packet for one destination is written on the interface the
 * path names and nowhere else. It used to go out on every interface at once:
 * each chunk of a file on every hub uplink, the LAN and BLE, five copies for
 * one recipient. With no path at all a broadcast is still right, since a
 * directly attached neighbour may forward it.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _FakeIface extends RnsInterface {
  _FakeIface(this._label, {bool uplink = false}) : _uplink = uplink;
  final String _label;
  final bool _uplink;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  bool get uplink => _uplink;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

void main() {
  test('a datagram follows its path onto ONE interface', () async {
    final hubA = _FakeIface('tcp:a', uplink: true);
    final hubB = _FakeIface('tcp:b', uplink: true);
    final lan = _FakeIface('lan');
    final t = RnsTransport()
      ..addInterface(hubA)
      ..addInterface(hubB)
      ..addInterface(lan);

    // X is reachable through a transport node heard on hub A.
    final x = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(x, 'cl', const ['x']);
    final relayed = RnsPacket(
      destHash: ann.destHash,
      data: ann.data,
      packetType: RnsPacketType.announce,
      headerType: RnsHeaderType.header2,
      transportType: RnsTransportType.transport,
      transportId: Uint8List(16)..[0] = 0x42,
      hops: 1,
    );
    expect(await t.ingest(relayed, 'tcp:a'), isNotNull);
    hubA.sent.clear();
    hubB.sent.clear();
    lan.sent.clear();

    t.sendDataTo(ann.destHash, Uint8List.fromList([1, 2, 3]));
    expect(hubA.sent.length, 1, reason: 'the path says hub A');
    expect(hubB.sent, isEmpty, reason: 'not the other hub');
    expect(lan.sent, isEmpty, reason: 'not the LAN');
    final p = RnsPacket.parse(hubA.sent.single)!;
    expect(p.headerType, RnsHeaderType.header2);
    expect(p.transportId, Uint8List(16)..[0] = 0x42);
  });

  test('with no path at all, every interface is tried', () async {
    final hubA = _FakeIface('tcp:a', uplink: true);
    final lan = _FakeIface('lan');
    final t = RnsTransport()
      ..addInterface(hubA)
      ..addInterface(lan);
    t.sendDataTo(Uint8List(16)..[3] = 7, Uint8List.fromList([9]));
    expect(hubA.sent.length, 1);
    expect(lan.sent.length, 1);
    expect(RnsPacket.parse(hubA.sent.single)!.headerType,
        RnsHeaderType.header1);
  });
}
