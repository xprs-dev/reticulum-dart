/*
 * The XPRS crypto primitive: short-Schnorr signatures over secp256k1, ECDH,
 * NIP-04 and the APRS-safe base85. XPRS.md section 9.1.2 is the specification.
 *
 * The standard BIP-340 signature is (R, s) = 64 bytes. XPRS uses the classic
 * Schnorr (e, s) form instead, where the challenge `e` is sent truncated to the
 * security level (16 bytes / 128-bit) and `s` is the full 32-byte scalar ->
 * 48 bytes. That is the smallest a secp256k1 signature can be (the scalar
 * cannot shrink), and it uses the SAME key behind the npub/callsign, so the
 * section 10 public-key beacon and callsign binding are unchanged.
 *
 * 48 bytes encodes to 60 chars in the APRS-safe base85 here (vs 64 for base64,
 * 86 for the 64-byte form), so the signature fits a single 67-char APRS line.
 *
 * This is an XPRS-specific scheme (NOT interoperable with BIP-340 verifiers);
 * only XPRS clients verify it. Math mirrors lib/util/nostr_crypto.dart.
 */

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class XprsCrypto {
  static final ECDomainParameters _curve = ECCurve_secp256k1();

  /// secp256k1 field prime.
  static final BigInt _p = BigInt.parse(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
      radix: 16);

  static final Random _rng = Random.secure();

  // ── big-endian conversions ───────────────────────────────────────────
  static BigInt _toBig(List<int> b) {
    var r = BigInt.zero;
    for (final x in b) {
      r = (r << 8) | BigInt.from(x);
    }
    return r;
  }

  static Uint8List _toBytes(BigInt v, int len) {
    final out = Uint8List(len);
    var t = v;
    final mask = BigInt.from(0xff);
    for (var i = len - 1; i >= 0; i--) {
      out[i] = (t & mask).toInt();
      t = t >> 8;
    }
    return out;
  }

  static Uint8List _sha256(List<int> b) =>
      Uint8List.fromList(sha256.convert(b).bytes);

  /// BIP-340-style tagged hash: sha256(sha256(tag) || sha256(tag) || msg).
  static Uint8List _taggedHash(String tag, List<int> msg) {
    final th = _sha256(utf8.encode(tag));
    return _sha256([...th, ...th, ...msg]);
  }

  /// lift_x: the even-y point with the given x (secp256k1), or null.
  static ECPoint? _liftX(BigInt x) {
    if (x <= BigInt.zero || x >= _p) return null;
    final c = (x.modPow(BigInt.from(3), _p) + BigInt.from(7)) % _p;
    final y = c.modPow((_p + BigInt.one) >> 2, _p); // p ≡ 3 (mod 4)
    if (y.modPow(BigInt.two, _p) != c) return null; // x not on curve
    final yEven = y.isEven ? y : (_p - y);
    return _curve.curve.createPoint(x, yEven);
  }

  /// The tagged-hash domain strings, XPRS.md section 9.1.2.
  ///
  /// The tag is hashed into the signature, so these two strings are as much a
  /// part of the wire format as the curve is. A verifier using different ones
  /// agrees with nobody.
  ///
  /// There were briefly two more, from before the protocol was renamed, and a
  /// verifier that tried the old challenge string after this one so that
  /// already-signed data kept validating. That transition is over: the old
  /// strings are gone and nothing produced under them verifies any more. What
  /// that cost is worth knowing, because it is not the usual "shows as
  /// unverified" -- the XPRS archive drops forged packets at flush and the
  /// courier drops forged carried mail, so every signature made before the cut
  /// was DISCARDED rather than doubted.
  static const _tagNonce = 'XPRS/nonce';
  static const _tagChallenge = 'XPRS/challenge';

  /// The x-only public key for scalar [d]: the 32-byte x coordinate of the
  /// even-y point, which is what `sig:` is verified against and what section
  /// 9.1.2 calls `px`. The x of d·G is the same whichever of d or n-d is used,
  /// so the parity only ever matters to the signer.
  static Uint8List publicKeyXOnly(BigInt d) =>
      _toBytes((_curve.G * d)!.x!.toBigInteger()!, 32);

  /// Sign a 32-byte message digest [m] with private scalar [d]. Returns the
  /// 48-byte signature (16-byte challenge ‖ 32-byte scalar).
  ///
  /// [auxOverride] exists for one caller: the test that reproduces section
  /// 9.1.2's worked example, which fixes aux to 32 zero bytes so every
  /// intermediate value is reproducible. Leave it null everywhere else -- aux
  /// only has to be unpredictable, and predictable aux with a real key is a
  /// nonce-reuse footgun.
  static Uint8List sign(Uint8List m, BigInt d, {Uint8List? auxOverride}) {
    final n = _curve.n;
    final g = _curve.G;
    // x-only key: use d' so that d'·G has even y (BIP-340 convention).
    var dp = d;
    var pPoint = (g * d)!;
    if (pPoint.y!.toBigInteger()!.isOdd) {
      dp = n - d;
      pPoint = (g * dp)!;
    }
    final px = _toBytes(pPoint.x!.toBigInteger()!, 32);

    // Deterministic-ish nonce with fresh aux randomness.
    final aux = auxOverride ?? Uint8List(32);
    if (auxOverride == null) {
      for (var i = 0; i < 32; i++) {
        aux[i] = _rng.nextInt(256);
      }
    }
    var k = _toBig(_taggedHash(_tagNonce, [..._toBytes(dp, 32), ...m, ...aux])) % n;
    if (k == BigInt.zero) k = BigInt.one;

    final r = (g * k)!;
    final rx = _toBytes(r.x!.toBigInteger()!, 32);

    // Challenge truncated to 16 bytes (128-bit).
    final ec = _taggedHash(_tagChallenge, [...rx, ...px, ...m]).sublist(0, 16);
    final e = _toBig(ec);

    final s = (k + e * dp) % n; // s·G - e·P = R, recoverable by the verifier
    return Uint8List.fromList([...ec, ..._toBytes(s, 32)]);
  }

  /// Verify a 48-byte signature [sig] on digest [m] for x-only pubkey [pubXonly].
  static bool verify(Uint8List m, Uint8List sig, Uint8List pubXonly) {
    try {
      if (sig.length != 48 || pubXonly.length != 32) return false;
      final n = _curve.n;
      final g = _curve.G;
      final ec = sig.sublist(0, 16);
      final e = _toBig(ec);
      final s = _toBig(sig.sublist(16, 48));
      if (s >= n) return false;

      final pPoint = _liftX(_toBig(pubXonly));
      if (pPoint == null) return false;

      // R' = s·G - e·P
      final sg = (g * s)!;
      final ep = (pPoint * e)!;
      final negEp = _curve.curve
          .createPoint(ep.x!.toBigInteger()!, _p - ep.y!.toBigInteger()!);
      final rPrime = sg + negEp;
      if (rPrime == null || rPrime.isInfinity) return false;

      final rx = _toBytes(rPrime.x!.toBigInteger()!, 32);
      final ec2 =
          _taggedHash(_tagChallenge, [...rx, ...pubXonly, ...m]).sublist(0, 16);
      // constant-time-ish compare
      var diff = 0;
      for (var i = 0; i < 16; i++) {
        diff |= ec[i] ^ ec2[i];
      }
      return diff == 0;
    } catch (_) {
      return false;
    }
  }

  // ── ECDH + AES-256-CBC encryption (NIP-04-style) ─────────────────────
  // Shared key = X coordinate of (our scalar × their point). The X coordinate
  // is parity-independent, so ecdh(a, B) == ecdh(b, A) without any y handling.
  // Confidentiality only; XPRS signs the ciphertext separately for integrity.

  // The ECDH secret is between two LONG-TERM keys (our scalar, their pubkey), so
  // it never changes for a given peer — unlike Reticulum's link ECDH, which uses
  // ephemeral keys and therefore can never be cached. Computing it is a
  // secp256k1 scalar multiplication: tens of milliseconds of pure-Dart curve
  // math, and it was being redone on EVERY encrypt/decrypt call. Cache it and a
  // peer costs one multiplication ever; every later message is symmetric-only.
  //
  // Keyed by (our scalar, their pubkey) so a profile switch cannot cross-wire
  // keys. Bounded LRU — a node talks to a bounded set of peers, and an unbounded
  // map here would be a memory leak fed by strangers.
  static final Map<String, Uint8List> _ecdhCache = {};
  static const int _ecdhCacheMax = 256;

  /// Number of real scalar multiplications performed (cache misses). Exposed so
  /// the host can prove the cache is working instead of assuming it.
  static int ecdhComputed = 0;

  /// The cached ECDH secret between our scalar [d] and a peer's x-only pubkey.
  /// Public so other transports (the NOSTR probe datagram) reuse this ONE cache
  /// rather than each keeping their own — the cache is the whole point.
  static Uint8List? ecdhShared(BigInt d, Uint8List pubXonly) =>
      _ecdhKey(d, pubXonly);

  static Uint8List? _ecdhKey(BigInt d, Uint8List pubXonly) {
    // Discriminate our scalar by a DIGEST, never by hashCode: a hashCode
    // collision between two different private keys would silently cross-wire
    // encryption keys. The digest also keeps the raw scalar out of a long-lived
    // map key.
    final ck = '${_scalarTag(d)}:${_hexOf(pubXonly)}';
    final hit = _ecdhCache[ck];
    if (hit != null) {
      // Refresh recency (insertion order = age).
      _ecdhCache.remove(ck);
      _ecdhCache[ck] = hit;
      return hit;
    }
    final p = _liftX(_toBig(pubXonly));
    if (p == null) return null;
    final s = p * d;
    if (s == null || s.isInfinity) return null;
    final key = _toBytes(s.x!.toBigInteger()!, 32);
    ecdhComputed++;
    _ecdhCache[ck] = key;
    while (_ecdhCache.length > _ecdhCacheMax) {
      _ecdhCache.remove(_ecdhCache.keys.first);
    }
    return key;
  }

  static String _hexOf(Uint8List b) =>
      b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();

  /// SHA-256 of our private scalar, truncated — a collision-resistant cache
  /// discriminator that does not retain the key itself.
  static String _scalarTag(BigInt d) {
    final tag = sha256.convert(_toBytes(d, 32)).bytes.sublist(0, 8);
    return _hexOf(Uint8List.fromList(tag));
  }

  static Uint8List _aesCbc(bool encrypt, Uint8List key, Uint8List iv, Uint8List data) {
    final c = PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()));
    c.init(encrypt,
        PaddedBlockCipherParameters(ParametersWithIV(KeyParameter(key), iv), null));
    return c.process(data);
  }

  /// Encrypt [plaintext] to x-only pubkey [pubXonly] using our scalar [d].
  /// Returns iv(16) ‖ ciphertext, or null on error.
  static Uint8List? encryptFor(BigInt d, Uint8List pubXonly, Uint8List plaintext) {
    final key = _ecdhKey(d, pubXonly);
    if (key == null) return null;
    final iv = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      iv[i] = _rng.nextInt(256);
    }
    try {
      final ct = _aesCbc(true, key, iv, plaintext);
      return Uint8List.fromList([...iv, ...ct]);
    } catch (_) {
      return null;
    }
  }

  /// Decrypt a [blob] (iv ‖ ciphertext) from x-only pubkey [pubXonly] with our
  /// scalar [d]. Returns the plaintext, or null on error.
  static Uint8List? decryptFrom(BigInt d, Uint8List pubXonly, Uint8List blob) {
    if (blob.length < 17) return null;
    final key = _ecdhKey(d, pubXonly);
    if (key == null) return null;
    try {
      final iv = Uint8List.fromList(blob.sublist(0, 16));
      final ct = Uint8List.fromList(blob.sublist(16));
      return _aesCbc(false, key, iv, ct);
    } catch (_) {
      return null;
    }
  }

  // ── NIP-04 (NOSTR kind-4 DM) wire format ─────────────────────────────────
  // Same crypto as encryptFor/decryptFrom (ECDH-secp256k1 shared X + AES-256-CBC)
  // but serialized as the standard NIP-04 content string
  // "<base64(ciphertext)>?iv=<base64(iv)>" so the events interoperate with the
  // NOSTR protocol. Used for the relay store-and-forward DM backup.

  /// NIP-04 encrypt [plaintext] to x-only pubkey [pubXonly] with our scalar [d].
  /// Returns the NIP-04 content string, or null on error.
  static String? nip04Encrypt(BigInt d, Uint8List pubXonly, Uint8List plaintext) {
    final key = _ecdhKey(d, pubXonly);
    if (key == null) return null;
    final iv = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      iv[i] = _rng.nextInt(256);
    }
    try {
      final ct = _aesCbc(true, key, iv, plaintext);
      return '${base64.encode(ct)}?iv=${base64.encode(iv)}';
    } catch (_) {
      return null;
    }
  }

  /// NIP-04 decrypt a [content] string (`b64ct?iv=b64iv`) from x-only
  /// pubkey [pubXonly] with our scalar [d]. Returns the plaintext, or null.
  static Uint8List? nip04Decrypt(BigInt d, Uint8List pubXonly, String content) {
    final sep = content.indexOf('?iv=');
    if (sep < 0) return null;
    final key = _ecdhKey(d, pubXonly);
    if (key == null) return null;
    try {
      final ct = base64.decode(content.substring(0, sep).trim());
      final iv = base64.decode(content.substring(sep + 4).trim());
      if (iv.length != 16) return null;
      return _aesCbc(
          false, key, Uint8List.fromList(iv), Uint8List.fromList(ct));
    } catch (_) {
      return null;
    }
  }

  // ── APRS-safe base85 (Z85-style: 4 bytes → 5 chars) ──────────────────
  // 85 printable chars, excluding space and APRS-reserved '{', '|', '~'.
  static const String _b85 =
      '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-+=^!/*?&<>()[]%\$#@,;_';

  static String b85encode(Uint8List data) {
    assert(data.length % 4 == 0);
    final sb = StringBuffer();
    for (var i = 0; i < data.length; i += 4) {
      var v = (data[i] << 24) |
          (data[i + 1] << 16) |
          (data[i + 2] << 8) |
          data[i + 3];
      v &= 0xFFFFFFFF;
      final digits = List<int>.filled(5, 0);
      var t = v;
      for (var j = 4; j >= 0; j--) {
        digits[j] = t % 85;
        t = t ~/ 85;
      }
      for (var j = 0; j < 5; j++) {
        sb.write(_b85[digits[j]]);
      }
    }
    return sb.toString();
  }

  static Uint8List? b85decode(String s) {
    if (s.isEmpty || s.length % 5 != 0) return null;
    final out = Uint8List((s.length ~/ 5) * 4);
    var oi = 0;
    for (var i = 0; i < s.length; i += 5) {
      var v = 0;
      for (var j = 0; j < 5; j++) {
        final d = _b85.indexOf(s[i + j]);
        if (d < 0) return null;
        v = v * 85 + d;
      }
      if (v > 0xFFFFFFFF) return null;
      out[oi++] = (v >> 24) & 0xff;
      out[oi++] = (v >> 16) & 0xff;
      out[oi++] = (v >> 8) & 0xff;
      out[oi++] = v & 0xff;
    }
    return out;
  }
}
