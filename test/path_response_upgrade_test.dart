import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _FakeIface extends RnsInterface {
  _FakeIface(this._label);
  final String _label;
  @override
  String get label => _label;
  @override
  bool get uplink => true;
  @override
  void send(Uint8List raw) {}
}

void main() {
  test('a hub path response replaces a longer relayed path', () async {
    final t = RnsTransport();
    t.addInterface(_FakeIface('tcp:far'));
    t.addInterface(_FakeIface('tcp:near'));
    final id = await RnsIdentity.generate();
    final a = await RnsAnnounceBuilder.build(id, 'xprs', const ['wapp']);
    final far = RnsPacket.parse(a.pack())!
      ..hops = 4
      ..headerType = RnsHeaderType.header2
      ..transportType = RnsTransportType.transport
      ..transportId = Uint8List.fromList(List.filled(16, 9));
    await t.ingest(far, 'tcp:far');
    expect(t.pathFor(a.destHash)!.hops, 5);
    final resp = RnsPacket.parse(a.pack())!
      ..hops = 1
      ..context = RnsContext.pathResponse
      ..headerType = RnsHeaderType.header2
      ..transportType = RnsTransportType.transport
      ..transportId = Uint8List.fromList(List.filled(16, 7));
    await t.ingest(resp, 'tcp:near');
    expect(t.pathFor(a.destHash)!.via, 'tcp:near');
    expect(t.pathFor(a.destHash)!.hops, 2);
  });
}
