/*
 * A payload that authenticates itself is delivered at once, not after a
 * twelve-second wait for the sender's path. The receiver of a packet-lane file
 * has often never heard the sender announce; every chunk used to sit out the
 * whole poll before the self-authenticating rule was even consulted.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Loop {
  late LxmfRouter router;
  Future<void> deliver(Uint8List raw) async {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    await router.handlePacket(p);
  }
}

void main() {
  test('unknown sender, self-authenticating payload: delivered without the wait',
      () async {
    final idA = await RnsIdentity.generate();
    final idB = await RnsIdentity.generate();
    final loopB = _Loop();
    final received = <LxmfMessage>[];
    var pathAsked = 0;

    loopB.router = LxmfRouter(
      identity: idB,
      send: (_) {},
      identityForDest: (_) => null, // B never heard A announce
      onMessage: received.add,
      acceptUnverified: (m) => m.fields.containsKey(0xB0),
      requestPath: (_) => pathAsked++,
    );

    final loopA = _Loop()
      ..router = LxmfRouter(
        identity: idA,
        send: (_) {},
        identityForDest: (h) =>
            RnsCrypto.constantTimeEquals(h, loopB.router.deliveryDestHash)
                ? idB
                : null,
      )
      ..router.pathIsLocal = ((_) => true);
    loopA.router.sendDataTo = (dest, ct) {
      final raw = RnsPacket(
        destHash: dest,
        data: ct,
        packetType: RnsPacketType.data,
        destType: RnsDestType.single,
      ).pack();
      loopB.deliver(raw);
    };

    final msg = await LxmfMessage.create(
      destinationHash: loopB.router.deliveryDestHash,
      source: idA,
      fields: {
        0xB0: ['xprs', Uint8List.fromList('t:file f:X1A b:AA'.codeUnits)],
      },
    );
    final sw = Stopwatch()..start();
    await loopA.router.deliver(msg, timeout: const Duration(seconds: 2));
    // Let the receive side run.
    final deadline = DateTime.now().add(const Duration(seconds: 3));
    while (received.isEmpty && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    sw.stop();
    expect(received.length, 1, reason: 'delivered');
    expect(sw.elapsed, lessThan(const Duration(seconds: 3)),
        reason: 'no twelve-second path poll on the way');
    expect(pathAsked, greaterThan(0),
        reason: 'the path is still requested so a reply has somewhere to go');
  });
}
