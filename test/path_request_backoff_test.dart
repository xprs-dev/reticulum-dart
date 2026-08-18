/*
 * Asking for a path costs the whole radio, so it is asked once.
 *
 * Measured on two phones with no internet: the same six destinations were
 * path-requested six times every twelve milliseconds, for hours. The node held
 * 49 DHT peers cached from when it had Wi-Fi, none reachable over the one radio
 * it had left, and every subsystem that wanted one asked again on every pass.
 * That storm pegged a full core on both phones (load average 21 on the weaker
 * one), starved the beacon to one per 75 seconds, and flooded the log ring so
 * hard it held only two minutes of history.
 *
 * The rule this pins down is the one docs/performance.md states twice: cache the
 * miss, not just the hit — and never put a cheap call in a hot loop.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Iface extends RnsInterface {
  _Iface(this._label);
  final String _label;
  final List<Uint8List> sent = [];
  @override
  String get label => _label;
  @override
  void send(Uint8List raw) => sent.add(raw);
}

Uint8List dest(int b) => Uint8List.fromList(List.filled(16, b));

void main() {
  late _Iface iface;
  late RnsTransport t;

  setUp(() {
    iface = _Iface('ble5');
    t = RnsTransport(transportId: Uint8List(16))..addInterface(iface);
  });

  test('a destination is asked for ONCE, however often callers ask', () {
    for (var i = 0; i < 200; i++) {
      t.requestPath(dest(0x11));
    }
    expect(iface.sent.length, 1,
        reason: 'every later ask inside the window is suppressed');
    expect(t.pathRequestsSuppressed, 199);
  });

  test('different destinations each get their own first ask', () {
    for (var d = 0; d < 6; d++) {
      for (var i = 0; i < 50; i++) {
        t.requestPath(dest(d));
      }
    }
    expect(iface.sent.length, 6, reason: 'six peers, six asks — not 300');
  });

  test('the global cap holds even with hundreds of distinct destinations', () {
    for (var d = 0; d < 300; d++) {
      t.requestPath(dest(d));
    }
    expect(iface.sent.length, lessThanOrEqualTo(20),
        reason: 'the radio is shared with everything else this device says');
    expect(t.pathRequestsSuppressed, greaterThan(250));
  });

  test('a delivery that just failed jumps the per-destination wait', () {
    t.requestPath(dest(0x22));
    expect(iface.sent.length, 1);
    t.requestPath(dest(0x22)); // ordinary retry — suppressed
    expect(iface.sent.length, 1);
    t.requestPath(dest(0x22), force: true); // somebody is waiting on this
    expect(iface.sent.length, 2);
  });

  test('an answered destination may be asked again immediately', () async {
    final id = await RnsIdentity.generate();
    final ann = await RnsAnnounceBuilder.build(id, 'backoff', const ['peer']);
    t.requestPath(ann.destHash);
    expect(iface.sent.length, 1);

    t.requestPath(ann.destHash);
    expect(iface.sent.length, 1, reason: 'still inside the wait');

    await t.ingest(ann, 'ble5'); // the peer answers
    expect(t.hasPath(ann.destHash), isTrue);

    // A later need (say the path is dropped by a failed delivery) must not be
    // stuck behind a backoff that belongs to a question already answered.
    t.pathFailed(ann.destHash);
    expect(iface.sent.length, greaterThan(1));
  });

  test('with no interfaces nothing is sent and nothing is counted', () {
    final bare = RnsTransport(transportId: Uint8List(16));
    bare.requestPath(dest(0x33));
    expect(bare.pathRequestsSuppressed, 0);
  });
}
