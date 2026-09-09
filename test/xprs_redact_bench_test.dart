/*
 * What one redaction key costs (XPRS.md 6.2.1).
 *
 * 6.2.1 fixes the price at 100000 iterations of PBKDF2-HMAC-SHA256 and says
 * why: "the derivation is the strength, and it costs everyone the same per
 * message". That number is not negotiable and nothing here changes it. What IS
 * negotiable is how much work each iteration does, and this prints it, because
 * docs/performance.md section 4 asks for a measured number rather than a
 * confident guess.
 *
 * Not an assertion of speed -- a phone and a laptop disagree by an order of
 * magnitude and a CI box is a third answer. It prints, and the number goes in
 * the commit message.
 *
 *   flutter test test/xprs_redact_bench_test.dart --plain-name derivation
 */
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as c;
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:reticulum/src/util/xprs_crypto.dart';

/// The reference the spec pins, computed the way the shipped code computes it.
Uint8List _pointycastle(String passphrase, Uint8List nonce) {
  final salt = Uint8List.fromList([...utf8.encode('xprs-xr'), ...nonce]);
  final kdf = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64))
    ..init(pc.Pbkdf2Parameters(salt, 100000, 16));
  return kdf.process(Uint8List.fromList(utf8.encode(passphrase)));
}

/// The same PBKDF2, with package:crypto's SHA-256 doing the compressions.
/// Still re-derives the HMAC pads per iteration -- this measures the digest,
/// not the structure.
Uint8List _cryptoHmac(String passphrase, Uint8List nonce) {
  final salt = Uint8List.fromList([...utf8.encode('xprs-xr'), ...nonce]);
  final mac = c.Hmac(c.sha256, utf8.encode(passphrase));
  var u = Uint8List.fromList(
      mac.convert([...salt, 0, 0, 0, 1]).bytes); // block index 1
  final acc = Uint8List.fromList(u);
  for (var i = 1; i < 100000; i++) {
    u = Uint8List.fromList(mac.convert(u).bytes);
    for (var j = 0; j < acc.length; j++) {
      acc[j] ^= u[j];
    }
  }
  return Uint8List.sublistView(acc, 0, 16);
}

void main() {
  final nonce = Uint8List.fromList(List.generate(12, (i) => i));
  const pass = XprsCrypto.kXrDefaultPassphrase;
  String hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  int msOf(Uint8List Function() f) {
    final sw = Stopwatch()..start();
    f();
    sw.stop();
    return sw.elapsedMilliseconds;
  }

  test('one derivation, three ways (prints ms)', () {
    // Warm the JIT/AOT paths once so the first number is not the compiler's.
    _pointycastle(pass, nonce);

    final shipped = msOf(() => XprsCrypto.xrKey(pass, nonce));
    final pcMs = msOf(() => _pointycastle(pass, nonce));
    final cryptoMs = msOf(() => _cryptoHmac(pass, nonce));

    // Whatever the numbers, every route must land on the spec's key.
    expect(hex(XprsCrypto.xrKey(pass, nonce)),
        'e7d6ef612e71fb09fd65dc71efd832c7');
    expect(hex(_pointycastle(pass, nonce)),
        'e7d6ef612e71fb09fd65dc71efd832c7');
    expect(hex(_cryptoHmac(pass, nonce)), 'e7d6ef612e71fb09fd65dc71efd832c7');

    // ignore: avoid_print
    print('xr derivation (100k iterations, one 16-byte block):\n'
        '  shipped XprsCrypto.xrKey : ${shipped} ms\n'
        '  pointycastle PBKDF2      : ${pcMs} ms\n'
        '  package:crypto HMAC loop : ${cryptoMs} ms');
  }, timeout: const Timeout(Duration(minutes: 5)));
}
