/*
 * Edge-bridge rebroadcast policy — locks the rule that a node bridging a
 * low-capacity EDGE (e.g. BLE) onto core (internet) interfaces propagates
 * announces heard on the edge UP onto core, but NEVER re-airs core-heard
 * announces back onto the edge (which would saturate BLE and starve the APRS
 * traffic that shares the radio) nor loop them across other core uplinks.
 * Default (non-bridge) transport behaviour is unchanged.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _FakeIface extends RnsInterface {
  _FakeIface(this._label, {bool edge = false}) : _edge = edge;
  final String _label;
  final bool _edge;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  bool get edge => _edge;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

Future<RnsPacket> _announce() async {
  final id = await RnsIdentity.generate();
  return RnsAnnounceBuilder.build(id, 'edgebridge', const ['peer']);
}

void main() {
  group('edge-bridge rebroadcast policy', () {
    test('edgeBridge: edge-heard announce goes ONLY to core, never to edge',
        () async {
      final core = _FakeIface('tcp');
      final edge = _FakeIface('ble', edge: true);
      final t = RnsTransport(transportId: Uint8List(16))
        ..edgeBridge = true
        ..addInterface(core)
        ..addInterface(edge);

      final ann = await _announce();
      final got = await t.ingest(ann, 'ble'); // heard on the edge
      expect(got, isNotNull, reason: 'a valid announce is accepted');

      expect(core.sent.length, 1, reason: 'propagated UP onto core');
      expect(edge.sent.length, 0, reason: 'never re-aired onto the edge');
    });

    test('edgeBridge: core-heard announce is NOT rebroadcast anywhere',
        () async {
      final core = _FakeIface('tcp');
      final core2 = _FakeIface('tcp2');
      final edge = _FakeIface('ble', edge: true);
      final t = RnsTransport(transportId: Uint8List(16))
        ..edgeBridge = true
        ..addInterface(core)
        ..addInterface(core2)
        ..addInterface(edge);

      final ann = await _announce();
      await t.ingest(ann, 'tcp'); // heard on a core uplink

      expect(edge.sent.length, 0, reason: 'never floods BLE');
      expect(core2.sent.length, 0, reason: 'no hub→hub loop across uplinks');
    });

    test('non-bridge transport rebroadcasts to all other interfaces (default)',
        () async {
      final a = _FakeIface('tcp');
      final b = _FakeIface('ble', edge: true);
      final t = RnsTransport(transportId: Uint8List(16))
        // edgeBridge stays false (default)
        ..addInterface(a)
        ..addInterface(b);

      final ann = await _announce();
      await t.ingest(ann, 'tcp'); // heard on a

      expect(b.sent.length, 1,
          reason: 'default transport relays onto every other interface');
    });
  });
}
