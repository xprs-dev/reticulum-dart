/*
 * A repeated LINKREQUEST must not re-key the link.
 *
 * The link id is a hash OF THE REQUEST, so a request that arrives twice — a BLE
 * retransmit, one copy per interface, or the initiator asking again because our
 * proof was lost — carries the same id both times. The ephemeral keypair minted
 * by RnsLink.responder does NOT repeat. So building a second responder link
 * silently re-keys an id the initiator has already proved against, and every
 * packet it sends from then on fails its HMAC.
 *
 * Measured on two phones over BLE5 with no internet: held mail was never picked
 * up, because the propagation pull request could not be decrypted —
 * "Token HMAC was invalid" out of LxmfRouter._onPropIn, repeating on both peers
 * for as long as they were in range. A message took 8.5 minutes to cross a room,
 * arriving only when a retry happened to open a link that was not clobbered.
 *
 * The fix is to answer a repeat with the CACHED proof and keep the first link.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// One side of a 2-node loopback. [duplicate] replays every packet it delivers,
/// which is what the radio does and what this regression is about.
class _Loop {
  _Loop({this.duplicate = false});
  final bool duplicate;
  late LxmfRouter router;
  final List<RnsPacket> _inbox = [];
  bool _pumping = false;
  int linkRequests = 0;

  void deliver(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    if (p.packetType == RnsPacketType.linkRequest) linkRequests++;
    _inbox.add(p);
    if (duplicate && p.packetType == RnsPacketType.linkRequest) {
      // The same bytes again — a retransmit, not a new request.
      final again = RnsPacket.parse(raw);
      if (again != null) _inbox.add(again);
    }
    _pump();
  }

  Future<void> _pump() async {
    if (_pumping) return;
    _pumping = true;
    while (_inbox.isNotEmpty) {
      final p = _inbox.removeAt(0);
      try {
        await router.handlePacket(p);
      } catch (_) {/* a wrong-peer packet is ignored, as on the wire */}
    }
    _pumping = false;
  }
}

void main() {
  test('a duplicated link request still lets held mail be pulled', () async {
    final idA = await RnsIdentity.generate(); // holds the mail
    final idB = await RnsIdentity.generate(); // pulls it

    // B's requests reach A twice; A's replies reach B once.
    final loopA = _Loop(duplicate: true);
    final loopB = _Loop();

    final received = <LxmfMessage>[];

    loopA.router = LxmfRouter(
      identity: idA,
      send: (raw) => loopB.deliver(raw),
      // A cannot resolve anyone, so its push has nowhere to go and the message
      // stays held for pickup — the situation the propagation path exists for.
      identityForDest: (_) => null,
    );
    loopB.router = LxmfRouter(
      identity: idB,
      send: (raw) => loopA.deliver(raw),
      identityForDest: (h) => _idFor(h, idA, idB),
      onMessage: received.add,
    );

    final msg = await LxmfMessage.create(
      destinationHash: loopB.router.deliveryDestHash,
      source: idA,
      content: 'UI-BLE-9',
    );
    expect(await loopA.router.send_(msg), isFalse,
        reason: 'no path: it must be held, not delivered');

    final got = await loopB.router.pullFrom(
      loopA.router.propagationDestHash,
      timeout: const Duration(seconds: 10),
    );

    expect(loopA.linkRequests + loopB.linkRequests, greaterThan(0),
        reason: 'the handshake has to have happened at all');
    expect(got, 1, reason: 'the duplicate request must not re-key the link');
    expect(received.length, 1);
    expect(String.fromCharCodes(received.single.content), 'UI-BLE-9');
  });
}

RnsIdentity? _idFor(Uint8List destHash, RnsIdentity a, RnsIdentity b) {
  for (final id in [a, b]) {
    for (final aspects in [
      const ['delivery'],
      const ['propagation'],
    ]) {
      final h = RnsDestination.hash(id, 'lxmf', aspects);
      if (RnsCrypto.constantTimeEquals(h, destHash)) return id;
    }
  }
  return null;
}
