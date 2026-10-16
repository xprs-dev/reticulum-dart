/*
 * Our own announces on a shared hub are rationed per destination
 * (RnsTransport.sendAnnounce): a hub mutes a destination that announces
 * faster than its rate target, so local interfaces get every announce and
 * each hub uplink at most one per destination per gap.
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
  late RnsTransport t;
  late _FakeIface lan, hub;
  final a = Uint8List.fromList(List.filled(16, 1));
  final b = Uint8List.fromList(List.filled(16, 2));
  final raw = Uint8List.fromList([1, 2, 3]);

  setUp(() {
    t = RnsTransport();
    lan = _FakeIface('lan');
    hub = _FakeIface('tcp:hub', uplink: true);
    t.addInterface(lan);
    t.addInterface(hub);
    t.ownUplinkAnnounceGap = const Duration(hours: 1);
  });

  test('a hub gets one announce per destination per gap, the LAN all', () {
    for (var i = 0; i < 5; i++) {
      t.sendAnnounce(raw, a);
    }
    expect(lan.sent.length, 5);
    expect(hub.sent.length, 1);
    expect(t.uplinkAnnouncesHeld, 4);
  });

  test('destinations are rationed separately', () {
    t.sendAnnounce(raw, a);
    t.sendAnnounce(raw, b);
    expect(hub.sent.length, 2);
  });

  test('after the gap the hub gets the next one', () {
    t.ownUplinkAnnounceGap = Duration.zero;
    t.sendAnnounce(raw, a);
    t.sendAnnounce(raw, a);
    expect(hub.sent.length, 2);
  });

  test('a new hub connection gets the first announce at once', () {
    t.sendAnnounce(raw, a);
    final again = _FakeIface('tcp:hub', uplink: true);
    t.removeInterface(hub);
    t.addInterface(again);
    t.sendAnnounce(raw, a);
    expect(again.sent.length, 1);
  });

  test('uplinks: false keeps it off every hub', () {
    t.sendAnnounce(raw, a, uplinks: false);
    expect(lan.sent.length, 1);
    expect(hub.sent.length, 0);
  });

  test('a path request carries its own tag on each interface', () {
    t.requestPath(a);
    expect(lan.sent.length, 1);
    expect(hub.sent.length, 1);
    final l = RnsPacket.parse(lan.sent.single)!.data;
    final h = RnsPacket.parse(hub.sent.single)!.data;
    expect(l.sublist(0, 16), a);
    expect(h.sublist(0, 16), a);
    expect(l.sublist(l.length - 16), isNot(h.sublist(h.length - 16)));
  });

  group('relaying onto a hub', () {
    late RnsTransport r;
    late _FakeIface rl, rh, rb;
    setUp(() {
      r = RnsTransport(transportId: Uint8List(16))..edgeQuiet = true;
      rl = _FakeIface('lan');
      rh = _FakeIface('tcp:hub', uplink: true);
      rb = _FakeIface('ble');
      r.addInterface(rl);
      r.addInterface(rh);
      r.addInterface(rb);
    });

    test('a LAN neighbour is not lifted onto a hub', () async {
      final id = await RnsIdentity.generate();
      await r.ingest(await RnsAnnounceBuilder.build(id, 'x', const ['y']), 'lan');
      expect(rh.sent, isEmpty);
      expect(rb.sent.length, 1);
    });

    test('a Bluetooth neighbour is, once per destination per gap', () async {
      final id = await RnsIdentity.generate();
      await r.ingest(await RnsAnnounceBuilder.build(id, 'x', const ['y']), 'ble');
      await r.ingest(await RnsAnnounceBuilder.build(id, 'x', const ['y']), 'ble');
      expect(rh.sent.length, 1);
      expect(rl.sent.length, 2);
    });
  });
}
