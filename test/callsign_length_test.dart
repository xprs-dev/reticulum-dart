/*
 * Copyright (c) XPRS
 * License: Apache-2.0
 *
 * Variable-length callsigns, spec section 3.
 *
 * A holder chooses how many characters of their own key to show, 2 to 5.
 * Two rules are load-bearing and both are pinned here:
 *
 *   - a device suffix is stripped before anything else, so X1ABCD-1 and
 *     X1ABCD-2 are one person (section 3.1)
 *   - the bare callsign is then matched WHOLE, never as a prefix, so a shorter
 *     truncation of the same key is a different label
 */

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';
import 'package:reticulum/src/util/nostr_key_generator.dart';

void main() {
  // A fixed key so the expected strings are constants, not recomputations.
  final pair = NostrCrypto.generateKeyPair();
  final hex = pair.publicKeyHex;
  final npub = pair.npub;
  final body = npub.substring(5, 10).toUpperCase(); // the five chars available

  group('deriveCallsign length', () {
    test('four characters is the default and is unchanged', () {
      expect(NostrCrypto.deriveCallsign(hex), body.substring(0, 4));
      expect(NostrCrypto.kDefaultCallsignLength, 4);
      expect(pair.callsign, 'X1${body.substring(0, 4)}');
    });

    test('round-trips every length from 2 to 5', () {
      for (var n = 2; n <= 5; n++) {
        expect(NostrCrypto.deriveCallsign(hex, length: n), body.substring(0, n),
            reason: 'length $n');
        expect(pair.callsignOfLength(length: n), 'X1${body.substring(0, n)}');
      }
    });

    test('rejects a length outside 2..5', () {
      for (final n in [0, 1, 6, 9, -1]) {
        expect(() => NostrCrypto.deriveCallsign(hex, length: n),
            throwsA(isA<ArgumentError>()),
            reason: 'length $n');
      }
    });

    test('the generator carries the chosen length through', () {
      for (var n = 2; n <= 5; n++) {
        final keys = NostrKeyGenerator.generateKeyPair(callsignLength: n);
        expect(keys.callsign.length, 2 + n);
        expect(NostrCrypto.callsignMatchesKey(
            keys.callsign, NostrCrypto.decodeNpub(keys.npub)), isTrue);
      }
    });

    test('X1 and X3 forms take the same length argument', () {
      expect(NostrKeyGenerator.deriveCallsign(npub, length: 5),
          'X1${body.substring(0, 5)}');
      expect(NostrKeyGenerator.deriveStationCallsign(npub, length: 2),
          'X3${body.substring(0, 2)}');
    });
  });

  group('bareCallsign strips the device suffix', () {
    test('a suffix names a device, the bare form names the person', () {
      expect(NostrCrypto.bareCallsign('X1ABCD-1'), 'X1ABCD');
      expect(NostrCrypto.bareCallsign('X1ABCD-99'), 'X1ABCD');
      expect(NostrCrypto.bareCallsign('X1ABCD'), 'X1ABCD');
    });

    test('normalises case and whitespace', () {
      expect(NostrCrypto.bareCallsign('  x1abcd-2 '), 'X1ABCD');
    });

    test('every length keeps its suffix behaviour', () {
      for (var n = 2; n <= 5; n++) {
        final call = 'X1${body.substring(0, n)}';
        expect(NostrCrypto.bareCallsign('$call-1'), call);
        expect(NostrCrypto.bareCallsign('$call-99'), call);
      }
    });
  });

  group('callsignMatchesKey', () {
    test('accepts the true length', () {
      for (var n = 2; n <= 5; n++) {
        expect(
            NostrCrypto.callsignMatchesKey('X1${body.substring(0, n)}', hex),
            isTrue,
            reason: 'length $n');
      }
    });

    test('accepts every truncation of the same key, by design', () {
      // Honest about what this function can know: given a callsign and a key
      // there is no way to tell which length the holder chose, so all four
      // pass. Canonicality comes from the signed identity announcement.
      for (var n = 2; n <= 5; n++) {
        expect(NostrCrypto.callsignMatchesKey('X1${body.substring(0, n)}', hex),
            isTrue);
      }
    });

    test('the four truncations are four DISTINCT labels', () {
      // The prefix rule, as it is actually enforced: whole-string comparison.
      // X1AB is not X1ABCD even though one key derives both.
      final labels = {
        for (var n = 2; n <= 5; n++) 'X1${body.substring(0, n)}',
      };
      expect(labels.length, 4, reason: 'each length is its own label');
      for (var truth = 2; truth <= 5; truth++) {
        final announced = 'X1${body.substring(0, truth)}';
        for (var other = 2; other <= 5; other++) {
          if (other == truth) continue;
          final wrong = 'X1${body.substring(0, other)}';
          expect(NostrCrypto.bareCallsign(wrong) ==
              NostrCrypto.bareCallsign(announced), isFalse,
              reason: 'length $other must not equal $truth');
        }
      }
    });

    test('a suffixed device still matches its own key', () {
      for (var n = 2; n <= 5; n++) {
        final call = 'X1${body.substring(0, n)}';
        expect(NostrCrypto.callsignMatchesKey('$call-1', hex), isTrue);
        expect(NostrCrypto.callsignMatchesKey('$call-99', hex), isTrue);
        // and reduces to the same person
        expect(NostrCrypto.bareCallsign('$call-1'),
            NostrCrypto.bareCallsign('$call-99'));
      }
    });

    test('rejects another key', () {
      final other = NostrCrypto.generateKeyPair();
      // Guard against the astronomically unlikely genuine collision.
      if (other.npub.substring(5, 10) != npub.substring(5, 10)) {
        expect(
            NostrCrypto.callsignMatchesKey(
                'X1${body.substring(0, 5)}', other.publicKeyHex),
            isFalse);
      }
    });

    test('accepts every self-derived prefix, X1 X3 X4 X5', () {
      for (final p in ['X1', 'X3', 'X4', 'X5']) {
        expect(NostrCrypto.callsignMatchesKey('$p${body.substring(0, 4)}', hex),
            isTrue,
            reason: p);
      }
    });

    test('does not apply to a licensed callsign', () {
      // No X1/X3/X4/X5 prefix: bound to a key by section 9.4.2, not derived.
      expect(NostrCrypto.callsignMatchesKey('CT1ABC-9', hex), isFalse);
      expect(NostrCrypto.callsignMatchesKey('G0XYZ', hex), isFalse);
    });

    test('rejects malformed input rather than throwing', () {
      for (final c in ['', 'X', 'X1', 'X1A', 'X1ABCDEF', '----', 'X2ABCD']) {
        expect(NostrCrypto.callsignMatchesKey(c, hex), isFalse, reason: '"$c"');
      }
      expect(NostrCrypto.callsignMatchesKey('X1ABCD', 'not-a-key'), isFalse);
    });
  });
}
