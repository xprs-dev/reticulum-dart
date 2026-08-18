// Which medium an outgoing RNS packet takes over BLE.
//
// Two phones with nothing but Bluetooth between them lost about half of every
// message they sent: each one fitted the advert cap, so it was aired once as a
// connectionless BLE advert — unacknowledged, never retransmitted, and heard
// only if the peer's scanner happened to be listening in that window. The link
// that was already open between them, acked and flow-controlled, carried
// nothing at all.
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/reticulum/rns_ble_interface.dart';

/// Packet type lives in the low two bits of the header byte.
Uint8List packet(int len, {bool announce = false}) {
  final p = Uint8List(len);
  p[0] = announce ? 0x01 : 0x00;
  for (var i = 1; i < len; i++) {
    p[i] = i & 0xFF;
  }
  return p;
}

class FakeRadio implements RnsBleRadio {
  FakeRadio({this.cap = 250, this.linkUp = false, this.unicastOk = true});

  final int cap;
  bool linkUp;
  bool unicastOk;

  final List<Uint8List> broadcasts = [];
  final List<Uint8List> unicasts = [];

  @override
  int get broadcastCap => cap;

  @override
  bool get hasLink => linkUp;

  @override
  void broadcast(Uint8List frame) => broadcasts.add(frame);

  @override
  bool unicast(Uint8List frame) {
    if (!unicastOk) return false;
    unicasts.add(frame);
    return true;
  }

  @override
  void onReceive(void Function(Uint8List frame) handler) {}
}

void main() {
  test('with a link up, an addressed packet takes the link', () {
    final radio = FakeRadio(linkUp: true);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100));
    expect(radio.unicasts.length, 1);
    expect(radio.broadcasts, isEmpty); // this is the bug that lost messages
  });

  test('an announce takes the link when we hold one', () {
    // It used to always broadcast, on the reasoning that every device in range
    // wants an announce. True — but the radio is half duplex, so this device
    // now transmits in a short window once a minute and an advert has to be
    // caught in that instant to count. A link is acknowledged, and the peer we
    // hold a link to is exactly the peer whose announce matters most. Anybody
    // else in range still hears the XPRS beacon and can dial us for the rest.
    final radio = FakeRadio(linkUp: true);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100, announce: true));
    expect(radio.unicasts.length, 1);
    expect(radio.broadcasts, isEmpty);
  });

  test('an announce still broadcasts when there is no link', () {
    // With nobody linked, the air is the only way to say we exist.
    final radio = FakeRadio();
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100, announce: true));
    expect(radio.broadcasts.length, 1);
    expect(radio.unicasts, isEmpty);
  });

  test('with no link, a packet that fits still broadcasts', () {
    final radio = FakeRadio();
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100));
    expect(radio.broadcasts.length, 1);
    expect(radio.unicasts, isEmpty);
  });

  test('an over-cap packet goes point-to-point even with no link', () {
    final radio = FakeRadio(cap: 80);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(300));
    expect(radio.unicasts.length, 1);
    expect(radio.broadcasts, isEmpty);
  });

  // A link the radio reports but cannot actually use must not swallow the
  // packet: falling through to the broadcast medium is what keeps a message
  // moving while a link is half-open.
  test('a refused link send falls back to broadcast', () {
    final radio = FakeRadio(linkUp: true, unicastOk: false);
    RnsBleInterface(radio: radio, onPacket: (_) {}).send(packet(100));
    expect(radio.broadcasts.length, 1);
  });

  test('an over-cap packet with no usable path is dropped, not truncated', () {
    final radio = FakeRadio(cap: 80, unicastOk: false);
    final iface = RnsBleInterface(radio: radio, onPacket: (_) {});
    iface.send(packet(300));
    expect(radio.broadcasts, isEmpty);
    expect(radio.unicasts, isEmpty);
    expect(iface.droppedCount, 1);
  });

  test('counters separate the two media', () {
    final radio = FakeRadio(linkUp: true);
    final iface = RnsBleInterface(radio: radio, onPacket: (_) {});
    iface.send(packet(100)); // link
    iface.send(packet(100, announce: true)); // link too, now
    expect(iface.unicastCount, 2);
    expect(iface.broadcastCount, 0);

    final airOnly = RnsBleInterface(radio: FakeRadio(), onPacket: (_) {})
      ..send(packet(100, announce: true));
    expect(airOnly.broadcastCount, 1, reason: 'no link — the air is all there is');
  });
}
