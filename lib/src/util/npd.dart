/*
 * NPD — NOSTR Probe Datagram.
 *
 * A connectionless, NOSTR-encrypted query that replaces a Reticulum link
 * handshake for the "do you have this?" case.
 *
 * WHY THIS EXISTS
 * ---------------
 * An idle phone was answering ~37 inbound link handshakes a minute, and the log
 * said what they were for: `relay: answered REQ -> 0 event(s)`, 98 times out of
 * 98. Every one spent a full Curve25519 handshake (2 scalar mults + an Ed25519
 * signature) to say "I have nothing". The link bought nothing: the relay uses it
 * as a plain byte pipe for one request and one response.
 *
 * A Reticulum link cannot be made cheaper, because its ECDH uses EPHEMERAL keys
 * — the cost repeats on every query, forever. But an ECDH between two LONG-TERM
 * NOSTR keys (our scalar, the peer's npub) is the SAME secret every time, so it
 * is computed once per peer and cached (see XprsCrypto._ecdhKey). After first
 * contact, an NPD exchange costs ZERO asymmetric crypto — just AES.
 *
 * And the responder simply STAYS SILENT when it holds nothing. A reply is itself
 * the signal that the peer has the data.
 *
 * WIRE FORMAT (carried as the payload of a PLAIN Reticulum packet)
 * ----------------------------------------------------------------
 *   cleartext header (60 B) — deliberately readable, so traffic stays
 *   classifiable on the wire even though its contents are not:
 *     magic(2)       'NP'
 *     version(1)
 *     type(1)        REQ / HAVE / RESULT
 *     senderPub(32)  our x-only NOSTR pubkey — tells the receiver which cached
 *                    ECDH key to use, and who to answer
 *     replyDest(16)  our RNS destination hash — lets the answer route back,
 *                    multi-hop, without the responder needing to look us up
 *     nonce(8)       random; also defeats the transport's packet-hash dedup,
 *                    which would otherwise silently drop identical probes
 *   body:
 *     iv(16)
 *     ciphertext     AES-256-CBC, key = HKDF-ish(sha256("NPD/enc" || ecdh))
 *     mac(32)        HMAC-SHA256 over header || iv || ciphertext
 *
 * ENCRYPT-THEN-MAC IS NOT OPTIONAL: AES-CBC alone is malleable, and this body is
 * attacker-reachable. The MAC covers the CLEARTEXT HEADER TOO, so type,
 * senderPub, replyDest and nonce cannot be tampered with (an attacker must not
 * be able to redirect a reply by rewriting replyDest).
 *
 * SIZE BUDGET: a HEADER_2 PLAIN packet leaves 500 - 35 = 465 B. Minus this
 * 60 B header, a 16 B IV and a 32 B MAC => ~357 B, and PKCS7 pads to a block, so
 * assume ~340 B of usable plaintext. A signed NOSTR event is routinely larger
 * than that, which is exactly why a hit normally answers HAVE and lets the peer
 * open a link for the bulk. The zero-result case — the one that was burning the
 * CPU — needs no reply at all.
 *
 * NOT FOR PRIVATE MAIL. The static-key ECDH has no forward secrecy (the same
 * property NIP-04 DMs already have): a leaked nsec decrypts past probes. That is
 * acceptable for queries about PUBLIC NOSTR data, and is precisely why LXMF is
 * out of scope for this transport.
 */
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

import 'xprs_crypto.dart';

/// Reticulum context byte for an NPD packet. Chosen from the range reference RNS
/// leaves free (it uses 0x00-0x0E and 0xFA-0xFF), so a reference transport node
/// forwards it without interpreting it.
const int kNpdContext = 0x30;

class NpdType {
  /// A query: "do you have anything matching this?"
  static const int req = 0x01;

  /// "Yes — n items, too big for a datagram. Open a link."
  static const int have = 0x02;

  /// "Yes — and here it is" (only when it fits; see the size budget).
  static const int result = 0x03;

  /// The type travels in CLEARTEXT so the kind of traffic on the wire stays
  /// classifiable; name it so it is readable in a log too.
  static String name(int t) => switch (t) {
        req => 'req',
        have => 'have',
        result => 'result',
        _ => 'type$t',
      };
}

const int _magic0 = 0x4E; // 'N'
const int _magic1 = 0x50; // 'P'
const int kNpdVersion = 1;

const int kNpdHeaderLen = 2 + 1 + 1 + 32 + 16 + 8; // 60
const int _ivLen = 16;
const int _macLen = 32;

/// Plaintext that still fits a single PLAIN packet after header/IV/MAC/padding.
/// Conservative: assumes the worst-case HEADER_2 (35 B) framing.
const int kNpdMaxPlaintext = 465 - kNpdHeaderLen - _ivLen - _macLen - 16;

final Random _rng = Random.secure();

/// A decoded NPD. [body] is the decrypted plaintext.
class Npd {
  final int type;
  final Uint8List senderPub; // x-only NOSTR pubkey (32)
  final Uint8List replyDest; // RNS destination hash (16)
  final Uint8List nonce; // 8
  final Uint8List body;

  const Npd({
    required this.type,
    required this.senderPub,
    required this.replyDest,
    required this.nonce,
    required this.body,
  });
}

/// Encode + encrypt an NPD to [peerPub] using our scalar [d].
///
/// The ECDH is served from [XprsCrypto]'s cache, so this is symmetric-only after
/// the first message to a given peer. Returns null if the body does not fit or
/// the peer key is unusable.
Uint8List? npdEncode({
  required int type,
  required BigInt d,
  required Uint8List senderPub,
  required Uint8List peerPub,
  required Uint8List replyDest,
  required Uint8List body,
  Uint8List? nonce,
  Uint8List? iv,
}) {
  if (senderPub.length != 32 || peerPub.length != 32) return null;
  if (replyDest.length != 16) return null;
  if (body.length > kNpdMaxPlaintext) return null;

  final shared = npdSharedSecret(d, peerPub);
  if (shared == null) return null;

  final n = nonce ?? _randomBytes(8);
  if (n.length != 8) return null;

  final header = BytesBuilder()
    ..addByte(_magic0)
    ..addByte(_magic1)
    ..addByte(kNpdVersion)
    ..addByte(type & 0xFF)
    ..add(senderPub)
    ..add(replyDest)
    ..add(n);
  final head = header.toBytes();

  final theIv = iv ?? _randomBytes(_ivLen);
  final ct = _aesCbc(true, _encKey(shared), theIv, body);

  // Encrypt-then-MAC, over the cleartext header as well: nobody may rewrite the
  // type or (critically) the replyDest to redirect our answer somewhere else.
  final macIn = BytesBuilder()
    ..add(head)
    ..add(theIv)
    ..add(ct);
  final mac = Hmac(sha256, _macKey(shared)).convert(macIn.toBytes()).bytes;

  return (BytesBuilder()
        ..add(head)
        ..add(theIv)
        ..add(ct)
        ..add(mac))
      .toBytes();
}

/// Parse the CLEARTEXT header only — no crypto. Lets a receiver reject junk, and
/// look up which cached ECDH key it needs, before spending anything.
({int type, Uint8List senderPub, Uint8List replyDest, Uint8List nonce})?
    npdPeek(Uint8List raw) {
  if (raw.length < kNpdHeaderLen + _ivLen + _macLen) return null;
  if (raw[0] != _magic0 || raw[1] != _magic1) return null;
  if (raw[2] != kNpdVersion) return null;
  return (
    type: raw[3],
    senderPub: Uint8List.sublistView(raw, 4, 36),
    replyDest: Uint8List.sublistView(raw, 36, 52),
    nonce: Uint8List.sublistView(raw, 52, 60),
  );
}

/// Verify + decrypt an NPD with our scalar [d]. Returns null on any failure —
/// bad magic, bad MAC, wrong key. A failed MAC must be indistinguishable from
/// junk to the caller.
Npd? npdDecode(Uint8List raw, BigInt d) {
  final head = npdPeek(raw);
  if (head == null) return null;

  final shared = npdSharedSecret(d, head.senderPub);
  if (shared == null) return null;

  final ivStart = kNpdHeaderLen;
  final ctStart = ivStart + _ivLen;
  final macStart = raw.length - _macLen;
  if (macStart <= ctStart) return null;

  final want = Hmac(sha256, _macKey(shared))
      .convert(Uint8List.sublistView(raw, 0, macStart))
      .bytes;
  final got = Uint8List.sublistView(raw, macStart);
  if (!_constantTimeEquals(want, got)) return null;

  try {
    final body = _aesCbc(
      false,
      _encKey(shared),
      Uint8List.sublistView(raw, ivStart, ctStart),
      Uint8List.sublistView(raw, ctStart, macStart),
    );
    return Npd(
      type: head.type,
      senderPub: Uint8List.fromList(head.senderPub),
      replyDest: Uint8List.fromList(head.replyDest),
      nonce: Uint8List.fromList(head.nonce),
      body: body,
    );
  } catch (_) {
    return null;
  }
}

/// The cached ECDH secret with [peerPub]. One secp256k1 multiplication per peer,
/// ever — see the class note.
Uint8List? npdSharedSecret(BigInt d, Uint8List peerPub) =>
    XprsCrypto.ecdhShared(d, peerPub);

// Domain-separate the two symmetric keys from each other (and from NIP-04, which
// uses the raw ECDH output as its AES key).
Uint8List _encKey(Uint8List shared) => Uint8List.fromList(
    sha256.convert([...utf8.encode('NPD/enc'), ...shared]).bytes);

Uint8List _macKey(Uint8List shared) => Uint8List.fromList(
    sha256.convert([...utf8.encode('NPD/mac'), ...shared]).bytes);

Uint8List _randomBytes(int n) {
  final b = Uint8List(n);
  for (var i = 0; i < n; i++) {
    b[i] = _rng.nextInt(256);
  }
  return b;
}

Uint8List _aesCbc(bool encrypt, Uint8List key, Uint8List iv, Uint8List data) {
  final c = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
  c.init(
      encrypt,
      PaddedBlockCipherParameters(
          ParametersWithIV(KeyParameter(key), iv), null));
  return c.process(data);
}

bool _constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
