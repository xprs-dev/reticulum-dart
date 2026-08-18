/*
 * A packet nobody acknowledged is not a delivery.
 *
 * A small message to a Bluetooth neighbour skips the handshake and goes as ONE
 * encrypted packet. That is the right thing to do on a radio — but nothing on
 * that path reports arrival, and the router used to return success for it. So
 * the sender logged "delivered over a direct link", queued no retry, and
 * dropped the matter entirely.
 *
 * Measured on two phones with no internet: C61's message reached TANK2, TANK2's
 * reply went out as one such packet, was recorded as delivered, and never
 * arrived. It was retried ZERO times, because nothing in the system believed
 * anything had gone wrong.
 *
 * Two properties are pinned here: the send reports sentUnconfirmed rather than
 * confirmed, and the held copy survives it so the recipient can still collect
 * the message on its next pull.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Loop {
  late LxmfRouter router;
  final List<RnsPacket> _inbox = [];
  bool _pumping = false;

  void deliver(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    _inbox.add(p);
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
  late RnsIdentity idA, idB;
  late _Loop loopA, loopB;
  late List<Uint8List> datagrams;
  late List<LxmfMessage> received;

  RnsIdentity? idFor(Uint8List destHash) {
    for (final id in [idA, idB]) {
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

  setUp(() async {
    idA = await RnsIdentity.generate();
    idB = await RnsIdentity.generate();
    datagrams = [];
    received = [];
    loopA = _Loop();
    loopB = _Loop();

    loopA.router = LxmfRouter(
      identity: idA,
      send: (raw) => loopB.deliver(raw),
      identityForDest: idFor,
    )
      // The Bluetooth case: a local path, and a datagram sink that swallows the
      // packet exactly like a radio that nobody is listening to.
      ..pathIsLocal = ((_) => true)
      ..sendDataTo = ((dest, data) => datagrams.add(data));
    loopB.router = LxmfRouter(
      identity: idB,
      send: (raw) => loopA.deliver(raw),
      identityForDest: idFor,
      onMessage: received.add,
    );
  });

  Future<LxmfMessage> note(String text) => LxmfMessage.create(
        destinationHash: loopB.router.deliveryDestHash,
        source: idA,
        content: text,
      );

  test('a single unacknowledged packet is NOT reported as delivered', () async {
    final outcome = await loopA.router.deliver(await note('on my way'));

    expect(outcome, LxmfDelivery.sentUnconfirmed,
        reason: 'nothing on that path says it arrived');
    expect(outcome, isNot(LxmfDelivery.confirmed));
    expect(datagrams, hasLength(1), reason: 'it really did go out');
  });

  test('the bool API reads it as "not delivered", so callers retry', () async {
    // Every caller of send_ treats false as "hold it and try again". That is
    // the behaviour an unacknowledged datagram needs.
    expect(await loopA.router.send_(await note('still nothing')), isFalse);
  });

  test('the held copy survives, so the peer can still collect it', () async {
    await loopA.router.deliver(await note('collect me'));

    // The radio ate the packet; the recipient asks for its mail instead.
    final got = await loopB.router.pullFrom(
      loopA.router.propagationDestHash,
      timeout: const Duration(seconds: 10),
    );

    expect(got, 1, reason: 'an unconfirmed send must not drop the held copy');
    expect(received.single.content, isNotEmpty);
    expect(String.fromCharCodes(received.single.content), 'collect me');
  });

  test('a confirmed link delivery still drops the held copy', () async {
    // Same message over a link that proves arrival: nothing to retry, nothing
    // to keep. The mailbox is empty afterwards, so a pull returns none.
    loopA.router = LxmfRouter(
      identity: idA,
      send: (raw) => loopB.deliver(raw),
      identityForDest: idFor,
    )..pathIsLocal = ((_) => false); // force the handshake path

    final outcome = await loopA.router.deliver(
      await note('over a link'),
      timeout: const Duration(seconds: 10),
    );
    expect(outcome, LxmfDelivery.confirmed);

    final got = await loopB.router.pullFrom(
      loopA.router.propagationDestHash,
      timeout: const Duration(seconds: 10),
    );
    expect(got, 0, reason: 'a proven delivery leaves nothing held');
  });
}
