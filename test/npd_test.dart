/*
 * NPD codec: the connectionless NOSTR-encrypted probe that replaces a link
 * handshake for "do you have this?".
 *
 * The security-relevant assertions here are the point of the file: a tampered
 * body OR a tampered cleartext header must both fail, and in particular nobody
 * may rewrite replyDest to redirect our answer at a victim.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

String _privHex(int seed) => '00${seed.toRadixString(16).padLeft(2, '0')}'
    '${'a3f19c8d2b4e6f70' * 3}1b2c';

BigInt _scalar(int seed) => BigInt.parse(_privHex(seed), radix: 16);

Uint8List _hexBytes(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List _pub(int seed) =>
    _hexBytes(NostrCrypto.derivePublicKey(_privHex(seed)));

Uint8List _dest(int b) => Uint8List(16)..fillRange(0, 16, b);

void main() {
  final alice = _scalar(11); // the querier
  final bob = _scalar(12); // the phone being probed
  final alicePub = _pub(11);
  final bobPub = _pub(12);
  final aliceDest = _dest(0xA1);

  Uint8List encodeReq(Uint8List body) => npdEncode(
        type: NpdType.req,
        d: alice,
        senderPub: alicePub,
        peerPub: bobPub,
        replyDest: aliceDest,
        body: body,
      )!;

  test('round-trips: bob decodes alice probe with his own scalar', () {
    final body = Uint8List.fromList('kinds:[1],authors:[abc]'.codeUnits);
    final raw = encodeReq(body);

    final got = npdDecode(raw, bob);
    expect(got, isNotNull);
    expect(got!.type, NpdType.req);
    expect(got.body, body);
    expect(got.senderPub, alicePub);
    expect(got.replyDest, aliceDest);
  });

  test('peek reads the cleartext header without any crypto', () {
    final raw = encodeReq(Uint8List.fromList([1, 2, 3]));
    final head = npdPeek(raw);
    expect(head, isNotNull);
    expect(head!.type, NpdType.req);
    expect(head.senderPub, alicePub);
    expect(head.replyDest, aliceDest,
        reason: 'the responder must know where to answer before decrypting');
  });

  test('a tampered CIPHERTEXT is rejected (MAC)', () {
    final raw = encodeReq(Uint8List.fromList('hello'.codeUnits));
    raw[kNpdHeaderLen + 20] ^= 0xFF; // flip a bit inside the body
    expect(npdDecode(raw, bob), isNull);
  });

  test('a tampered replyDest is rejected — no redirecting our answer', () {
    final raw = encodeReq(Uint8List.fromList('hello'.codeUnits));
    // replyDest lives at offset 36..52 in the CLEARTEXT header. If the MAC did
    // not cover the header, an attacker could point our reply at a victim and
    // turn every probe into an amplification vector.
    raw[36] ^= 0xFF;
    expect(npdDecode(raw, bob), isNull);
  });

  test('a tampered TYPE is rejected', () {
    final raw = encodeReq(Uint8List.fromList('hello'.codeUnits));
    raw[3] = NpdType.result; // was REQ
    expect(npdDecode(raw, bob), isNull);
  });

  test('a third party with a valid key cannot decode it', () {
    final eve = _scalar(13);
    final raw = encodeReq(Uint8List.fromList('private-ish'.codeUnits));
    expect(npdDecode(raw, eve), isNull);
  });

  test('junk and truncation are rejected without throwing', () {
    expect(npdDecode(Uint8List(0), bob), isNull);
    expect(npdDecode(Uint8List(59), bob), isNull);
    expect(npdPeek(Uint8List.fromList(List.filled(200, 0x41))), isNull);
  });

  test('a body larger than one packet is refused, not silently truncated', () {
    final tooBig = Uint8List(kNpdMaxPlaintext + 1);
    final raw = npdEncode(
      type: NpdType.req,
      d: alice,
      senderPub: alicePub,
      peerPub: bobPub,
      replyDest: aliceDest,
      body: tooBig,
    );
    expect(raw, isNull, reason: 'caller must fall back to a link, not corrupt');
  });

  test('the whole datagram fits inside a single PLAIN Reticulum packet', () {
    final body = Uint8List(kNpdMaxPlaintext);
    final raw = encodeReq(body);
    // 500 MTU - 35 B worst-case HEADER_2 framing.
    expect(raw.length, lessThanOrEqualTo(465));
  });

  test('steady state costs ZERO scalar mults — the reason NPD exists', () {
    // Warm both directions once.
    npdDecode(encodeReq(Uint8List.fromList([1])), bob);
    final before = XprsCrypto.ecdhComputed;
    for (var i = 0; i < 25; i++) {
      final raw = encodeReq(Uint8List.fromList([i]));
      expect(npdDecode(raw, bob), isNotNull);
    }
    expect(XprsCrypto.ecdhComputed, before,
        reason: '25 probe exchanges must cost no asymmetric crypto at all');
  });
}
