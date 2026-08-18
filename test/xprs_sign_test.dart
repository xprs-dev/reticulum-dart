/*
 * XPRS signatures against the specification's own worked example.
 *
 * XPRS.md section 9.1.2 fixes `aux` to 32 zero bytes and uses the toy key
 * d = 7 precisely so that every intermediate value is reproducible and an
 * implementation can be checked against the document rather than against
 * another implementation. That distinction is not academic: this signer and
 * the ESP32 codec agreed with each other for months while both used the
 * pre-rename tagged-hash strings, so signatures either produced read as forged
 * under the specification, and the document's own example read as forged to
 * both. Two implementations agreeing proves only that they are the same, and
 * this file is what stops that being mistaken for correctness.
 */

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:reticulum/reticulum.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List _unhex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  // The canonical text is the packet with sig: and via: removed (section 5),
  // which is also what the identifier truncates -- one form serves both.
  const canonical = 't:message f:X1QZ3N d:LISBOA ts:2026-08-08_14:26:40 '
      'm:net starts in ten minutes';
  const wantM =
      '39922745225b987201d0a253ed152b99712088ba6c578a41bdfc670594a3c553';
  const wantPx =
      '5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc';
  const wantSig = 'b40348c6defc8e1ae6dfca7635513e3b'
      'e052dd3b72c2aab12db5d39d047de1816f15f396a402ea9d2d3407bde0dd5df8';
  const wantB85 =
      'V<-(s&U-xL(hjs8hbML0<8nw[A)a<YeW+5_1BYlWzX.)fQYP&LeI[ZC<n4Yl';

  final d = BigInt.from(7);
  final m = Uint8List.fromList(sha256.convert(utf8.encode(canonical)).bytes);

  test('the canonical text hashes to the document m', () {
    expect(_hex(m), wantM);
    // Section 6.3: the identifier is the first six characters of the same
    // digest, which is why one canonical form serves signing and identity.
    expect(_hex(m).substring(0, 6), '399227');
  });

  test('the toy key gives the document px', () {
    expect(_hex(XprsCrypto.publicKeyXOnly(d)), wantPx);
  });

  test('signing with aux fixed to zero reproduces the document', () {
    final sig = XprsCrypto.sign(m, d, auxOverride: Uint8List(32));
    expect(_hex(sig), wantSig,
        reason: 'check the tagged-hash domain strings in section 9.1.2');
  });

  test('the document signature encodes to the document base85', () {
    expect(XprsCrypto.b85encode(_unhex(wantSig)), wantB85);
    expect(_hex(XprsCrypto.b85decode(wantB85)!), wantSig);
  });

  test('the document signature verifies', () {
    expect(XprsCrypto.verify(m, _unhex(wantSig), _unhex(wantPx)), isTrue);
  });

  test('a fresh signature verifies and differs each time', () {
    final a = XprsCrypto.sign(m, d);
    final b = XprsCrypto.sign(m, d);
    final px = XprsCrypto.publicKeyXOnly(d);
    expect(XprsCrypto.verify(m, a, px), isTrue);
    expect(XprsCrypto.verify(m, b, px), isTrue);
    // aux is random, so the same packet signed twice gives two signatures.
    expect(_hex(a), isNot(_hex(b)));
  });

  test('a tampered digest does not verify', () {
    final bad = Uint8List.fromList(m);
    bad[0] ^= 0x01;
    expect(XprsCrypto.verify(bad, _unhex(wantSig), _unhex(wantPx)), isFalse);
  });

  test('a signature under any other domain string does not verify', () {
    // The tags are hashed into the challenge, so they are as much a part of the
    // wire format as the curve is. There was briefly a fallback here that also
    // tried the pre-rename challenge string, so that already-signed data kept
    // validating; it has been removed, and this is what stands in its place.
    // Nothing signed under the old strings verifies any more -- and in this
    // system that means DISCARDED, not merely unbadged: the XPRS archive drops
    // forged packets at flush and the courier drops forged carried mail.
    const preRenameDigest =
        '8c012bc0f0f3919ab65e7867c5b394194d1eed28c593b1ccd456ec8532650a07';
    const preRenamePx =
        '4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff';
    const preRenameSig =
        'fad545192d362ec74b79a6c621ea8169afce898c6f45ddf3080bd258d29108a7'
        'fca82021d4ecc12aa033e53715176bf3';
    expect(
        XprsCrypto.verify(_unhex(preRenameDigest), _unhex(preRenameSig),
            _unhex(preRenamePx)),
        isFalse,
        reason: 'a fallback to a second challenge string has come back');
  });
}
