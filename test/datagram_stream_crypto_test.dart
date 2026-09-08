/*
 * A stream of packets to one peer pays the curve once. The encryptor keeps
 * one ephemeral key and derived secret; every packet still gets its own IV and
 * decrypts with the ordinary Identity.decrypt, which caches the derived key by
 * ephemeral public key. And an unsigned LXMF envelope is delivered under the
 * receiver's self-authenticating rule, known sender or not.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  test('encryptor round-trips many packets under one ephemeral key', () async {
    final bob = await RnsIdentity.generate();
    final enc = await bob.encryptor();
    final a = enc.encrypt(Uint8List.fromList([1, 2, 3]));
    final b = enc.encrypt(Uint8List.fromList([4, 5, 6, 7]));
    expect(a.sublist(0, 32), b.sublist(0, 32), reason: 'same ephemeral key');
    expect(a.sublist(32), isNot(b.sublist(32)), reason: 'fresh IV each');
    expect(await bob.decrypt(a), [1, 2, 3]);
    expect(await bob.decrypt(b), [4, 5, 6, 7]);
    // And the classic per-packet form still opens.
    final c = await bob.encrypt(Uint8List.fromList([9]));
    expect(await bob.decrypt(c), [9]);
  });

  test('an unsigned wapp datagram is delivered under acceptUnverified even '
      'from a KNOWN sender', () async {
    final alice = await RnsIdentity.generate();
    final bob = await RnsIdentity.generate();
    final got = <LxmfMessage>[];
    final router = LxmfRouter(
      identity: bob,
      send: (_) {},
      identityForDest: (_) => alice, // sender known: verify would run
      onMessage: got.add,
      acceptUnverified: (m) => m.fields.containsKey(0xB0),
    );
    final msg = await LxmfMessage.create(
      destinationHash: router.deliveryDestHash,
      source: alice,
      fields: {0xB0: ['xprs', Uint8List.fromList([7, 7])]},
      sign: false,
    );
    expect(msg.signature.every((b) => b == 0), isTrue);
    final ct = await bob.encrypt(msg.packed);
    await router.handlePacket(RnsPacket(
      destHash: router.deliveryDestHash,
      data: ct,
      packetType: RnsPacketType.data,
      destType: RnsDestType.single,
    ));
    expect(got.length, 1);
    // An unsigned CHAT (no 0xB0) from a known sender is still refused.
    final chat = await LxmfMessage.create(
      destinationHash: router.deliveryDestHash,
      source: alice,
      content: 'hi',
      sign: false,
    );
    await router.handlePacket(RnsPacket(
      destHash: router.deliveryDestHash,
      data: await bob.encrypt(chat.packed),
      packetType: RnsPacketType.data,
      destType: RnsDestType.single,
    ));
    expect(got.length, 1);
  });
}
