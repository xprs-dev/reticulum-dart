/*
 * A quiet client (a browser on a gateway's WebSocket) pays for every byte.
 * The node's own announces reach it as the answer to its path request, not
 * as a stream: measured 2026-11-27, an idle page received twenty announces a
 * minute, three times its own traffic.
 */
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:reticulum/reticulum.dart';

class _Iface extends RnsInterface {
  _Iface(this._label, {this.q = false});
  final String _label;
  final bool q;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  bool get quiet => q;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

RnsPacket _pathRequest(Uint8List dest) {
  final probeIface = _Iface('probe');
  RnsTransport()
    ..addInterface(probeIface)
    ..requestPath(dest);
  return RnsPacket.parse(probeIface.sent.single)!;
}

void main() {
  test('own announces reach a quiet client only after it asks for a path',
      () async {
    final lan = _Iface('lan');
    final web = _Iface('web', q: true);
    final t = RnsTransport(transportId: Uint8List(16)..[0] = 1)
      ..addInterface(lan)
      ..addInterface(web);
    final me = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(me, 'quiet', const ['x']);
    final raw = ann.pack();

    t.sendAnnounce(raw, ann.destHash);
    expect(lan.sent.length, 1);
    expect(web.sent, isEmpty, reason: 'nothing it did not ask for');
    expect(t.quietAnnouncesHeld, 1);

    // It asks; the host answers by announcing its destinations.
    var asked = 0;
    t.onPathRequest = (_) => asked++;
    await t.ingest(_pathRequest(ann.destHash), 'web');
    expect(asked, 1);
    t.sendAnnounce(raw, ann.destHash);
    expect(web.sent.length, 1, reason: 'the answer to its request');

    // The window over, it is quiet again.
    t.quietAnnounceWindow = Duration.zero;
    await Future<void>.delayed(const Duration(milliseconds: 5));
    t.sendAnnounce(raw, ann.destHash);
    expect(web.sent.length, 1);
    expect(lan.sent.length, 3, reason: 'a LAN peer hears every one');
  });

  test('a request from another interface opens nothing for the quiet one',
      () async {
    final lan = _Iface('lan');
    final web = _Iface('web', q: true);
    final t = RnsTransport(transportId: Uint8List(16)..[0] = 1)
      ..addInterface(lan)
      ..addInterface(web);
    final me = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(me, 'quiet', const ['x']);
    t.onPathRequest = (_) {};
    await t.ingest(_pathRequest(ann.destHash), 'lan');
    t.sendAnnounce(ann.pack(), ann.destHash);
    expect(web.sent, isEmpty);
  });
}
