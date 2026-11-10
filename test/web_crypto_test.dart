// Reticulum's crypto compiled to JavaScript (the browser build, rns.js): the
// steps an announce and a link take, checked in a browser.
//   dart test -p chrome test/web_crypto_test.dart
@TestOn('browser')
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Cryptography;
import 'package:cryptography/dart.dart' show DartCryptography;
import 'package:reticulum/src/services/reticulum/rns_announce.dart';
import 'package:reticulum/src/services/reticulum/rns_crypto.dart';
import 'package:reticulum/src/services/reticulum/rns_identity.dart';
import 'package:reticulum/src/services/reticulum/rns_packet.dart';
import 'package:test/test.dart';

void main() {
  // The default instance: the browser's Web Crypto where it offers the algorithm.
  setUpAll(() => Cryptography.instance);

  test('hashes', () {
    expect(RnsCrypto.fullHash(Uint8List.fromList([1, 2, 3])).length, 32);
  });

  test('sign and validate', () async {
    final id = await RnsIdentity.generate();
    final msg = Uint8List.fromList(List.generate(100, (i) => i));
    final sig = await id.sign(msg);
    expect(await RnsIdentity.fromPublicKey(id.getPublicKey()).validate(sig, msg), isTrue);
  });

  test('an announce built here validates here', () async {
    final id = await RnsIdentity.generate();
    final pkt = await RnsAnnounceBuilder.build(id, 'xprs', ['wapp']);
    final parsed = RnsPacket.parse(pkt.pack())!;
    final destHash = RnsDestination.hash(id, 'xprs', ['wapp']);
    expect(parsed.destHash, destHash, reason: 'the destination hash');
    expect(await validateAnnounce(parsed), isNotNull);
  });
}
