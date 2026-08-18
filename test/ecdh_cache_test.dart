/*
 * The ECDH shared secret between two LONG-TERM NOSTR keys never changes, so it
 * must be computed once per peer and cached forever. This is the whole basis of
 * the connectionless probe: Reticulum's link ECDH uses EPHEMERAL keys and can
 * never be cached (2-3 scalar mults per query, forever), while this one
 * amortises to zero asymmetric crypto.
 *
 * These tests assert the amortisation actually happens — the earlier code
 * recomputed the multiplication on every single call.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// A valid secp256k1 scalar (well below the curve order) from a seed byte.
String _privHex(int seed) =>
    '00${seed.toRadixString(16).padLeft(2, '0')}'
    '${'a3f19c8d2b4e6f70' * 3}${'1b2c'}';

BigInt _scalar(int seed) => BigInt.parse(_privHex(seed), radix: 16);

Uint8List _hexBytes(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// x-only pubkey for a scalar, via the same derivation NOSTR uses.
Uint8List _pub(int seed) =>
    _hexBytes(NostrCrypto.derivePublicKey(_privHex(seed)));

void main() {
  test('the shared secret is computed ONCE per peer, then served from cache',
      () {
    final mine = _scalar(1);
    final theirs = _pub(2);
    final msg = Uint8List.fromList('do you have this hash?'.codeUnits);

    final before = XprsCrypto.ecdhComputed;
    final ct = XprsCrypto.nip04Encrypt(mine, theirs, msg);
    expect(ct, isNotNull);
    final afterFirst = XprsCrypto.ecdhComputed;
    expect(afterFirst - before, 1,
        reason: 'first contact with a peer costs exactly one scalar mult');

    // Every subsequent message to the SAME peer must be symmetric-only.
    for (var i = 0; i < 20; i++) {
      XprsCrypto.nip04Encrypt(mine, theirs, msg);
      XprsCrypto.nip04Decrypt(mine, theirs, ct!);
    }
    expect(XprsCrypto.ecdhComputed, afterFirst,
        reason: '40 further ops must cost ZERO scalar mults — this is the win');
  });

  test('round-trips, and both ends derive the same key', () {
    final a = _scalar(3);
    final b = _scalar(4);
    final msg = Uint8List.fromList('probe payload'.codeUnits);

    final ct = XprsCrypto.nip04Encrypt(a, _pub(4), msg);
    expect(ct, isNotNull);
    // ecdh(a, B) == ecdh(b, A): the responder decrypts with ITS scalar and the
    // sender's pubkey — which is exactly how the probe responder works.
    final back = XprsCrypto.nip04Decrypt(b, _pub(3), ct!);
    expect(back, isNotNull);
    expect(back, msg);
  });

  test('a third party cannot read a message addressed to someone else', () {
    final mine = _scalar(5);
    final eve = _scalar(7);
    final msg = Uint8List.fromList('secret'.codeUnits);

    final toPeer6 = XprsCrypto.nip04Encrypt(mine, _pub(6), msg)!;
    // Eve holds a valid key, just not the right one.
    final wrong = XprsCrypto.nip04Decrypt(eve, _pub(5), toPeer6);
    expect(wrong, isNot(msg));
  });
}
