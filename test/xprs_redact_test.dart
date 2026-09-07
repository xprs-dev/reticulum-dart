import 'dart:typed_data';

import 'package:reticulum/src/util/xprs_crypto.dart';
import 'package:flutter_test/flutter_test.dart';

/// XPRS §9.2.1 — redacted packets (`((secret))` → `█` bars + `xr:`).
void main() {
  String hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  group('the spec worked vector (§9.2.1)', () {
    // nonce fixed to 000102030405060708090a0b so every value reproduces.
    final nonce = Uint8List.fromList(List.generate(12, (i) => i));
    const xr = 'AAECAwQFBgcICQoL5tqwc_xiDDNhLVD9YLDyKZnrvw';
    // The barred wire the author airs; the default passphrase decrypts it.
    const barredWire = 't:message f:X1QZ3N d:X1RD89 pos:38.7███,-9.1███ '
        'ts:2026-08-18_17:00:00 '
        'xr:AAECAwQFBgcICQoL5tqwc_xiDDNhLVD9YLDyKZnrvw m:meet ███ at █████';

    test('the derived key matches the spec byte for byte', () {
      final k = XprsCrypto.xrKey(XprsCrypto.kXrDefaultPassphrase, nonce);
      expect(hex(k), 'e7d6ef612e71fb09fd65dc71efd832c7');
    });

    test('xrSecrets recovers the hidden pieces in packet order', () {
      final s = XprsCrypto.xrSecrets(xr, XprsCrypto.kXrDefaultPassphrase);
      expect(s, ['223', '393', 'Max', 'pier2']);
    });

    test('restore refills every bar run across the whole wire', () {
      final r =
          XprsCrypto.restore(barredWire, xr, XprsCrypto.kXrDefaultPassphrase);
      expect(r, contains('pos:38.7223,-9.1393'));
      expect(r, contains('m:meet Max at pier2'));
    });

    test('the wrong passphrase fails the -> sentinel (no restore)', () {
      expect(XprsCrypto.xrSecrets(xr, 'not the passphrase'), isNull);
      expect(XprsCrypto.restore(barredWire, xr, 'not the passphrase'), isNull);
    });
  });

  group('redact → restore round trip', () {
    test('a message body, default passphrase', () {
      final nonce = Uint8List.fromList(List.filled(12, 7));
      final red = XprsCrypto.redact('meet ((Max)) at ((pier2))', nonce: nonce);
      expect(red, isNotNull);
      final (barred, xr) = red!;
      // bars, one per hidden character, in place
      expect(barred, 'meet ███ at █████');
      expect(XprsCrypto.hasBars(barred), isTrue);
      // and they come back
      final back =
          XprsCrypto.restore(barred, xr, XprsCrypto.kXrDefaultPassphrase);
      expect(back, 'meet Max at pier2');
    });

    test('a real passphrase, and a wrong one does not open it', () {
      final red = XprsCrypto.redact('the code is ((1234))',
          passphrase: 'hunter2');
      final (barred, xr) = red!;
      expect(barred, 'the code is ████');
      expect(XprsCrypto.restore(barred, xr, 'hunter2'), 'the code is 1234');
      expect(XprsCrypto.restore(barred, xr, 'wrong'), isNull);
    });

    test('nothing marked → nothing to redact', () {
      expect(XprsCrypto.redact('just plain words'), isNull);
    });

    test('a multi-byte secret is barred per character, not per byte', () {
      final red = XprsCrypto.redact('wave ((😀🌊))'); // two code points
      final (barred, xr) = red!;
      expect(barred, 'wave ██');
      expect(XprsCrypto.restore(barred, xr, XprsCrypto.kXrDefaultPassphrase),
          'wave 😀🌊');
    });
  });

  group('restoration is defended', () {
    test('a piece whose length != its hole is refused, bars stand', () {
      // Build a valid blob for a 3-char secret, then apply it to a 5-bar hole.
      final red = XprsCrypto.redact('x ((abc))'); // 3 bars
      final (_, xr) = red!;
      final wrongHole = 'x █████'; // 5 bars — cannot take a 3-char piece
      expect(
          XprsCrypto.restore(wrongHole, xr, XprsCrypto.kXrDefaultPassphrase),
          isNull);
    });

    test('more pieces than holes is refused', () {
      final red = XprsCrypto.redact('a ((one)) b ((two))'); // two pieces
      final (_, xr) = red!;
      final oneHole = 'a ███ b two'; // only one hole
      expect(XprsCrypto.restore(oneHole, xr, XprsCrypto.kXrDefaultPassphrase),
          isNull);
    });
  });
}
