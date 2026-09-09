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

  // ── §9.2.1 redacted packets: obfuscated ((...)) spans ─────────────────
  //
  // Each ((secret)) becomes a run of the block bar █ (U+2588), one per hidden
  // character, in place. The hidden pieces travel in `xr:` = base64url(no pad)
  // of nonce(12) ‖ AES-128-CTR ciphertext of "->" followed by the pieces, one
  // line per bar run in packet order. Key = first 16 bytes of
  // PBKDF2-HMAC-SHA256(passphrase, "xprs-xr" ‖ nonce, 100000). Success is the
  // "->" sentinel: a wrong passphrase yields garbage that fails it. The default
  // passphrase is sixteen '#': obfuscation, not secrecy — anyone can decrypt it,
  // but each message still costs the full derivation.

  static const String kXrDefaultPassphrase = '################';
  static const int _xrBarRune = 0x2588; // █

  static Uint8List _randBytes(int n) {
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = _rng.nextInt(256);
    }
    return b;
  }

  /// PBKDF2-HMAC-SHA256(passphrase, "xprs-xr" ‖ nonce, 100000), first 16 bytes.
  ///
  /// THE 100000 IS THE POINT AND IS NOT NEGOTIABLE (section 6.2.1: "the
  /// derivation is the strength, and it costs everyone the same per message").
  /// What is negotiable is the work spent inside each of those iterations, and
  /// a general-purpose HMAC spends twice what it needs to here: PBKDF2 hashes
  /// with ONE key a hundred thousand times, and a stock HMAC re-compresses
  /// both 64-byte pad blocks on every single call to re-derive a state that
  /// cannot have changed. Keeping the two pad midstates makes an iteration two
  /// SHA-256 compressions instead of four.
  ///
  /// Same algorithm, same salt, same iteration count, same bytes out --
  /// section 6.2.1's worked vector pins the answer to
  /// `e7d6ef612e71fb09fd65dc71efd832c7` and the test asserts it.
  static Uint8List xrKey(String passphrase, Uint8List nonce) {
    final salt = Uint8List.fromList([...utf8.encode('xprs-xr'), ...nonce]);
    var key = Uint8List.fromList(utf8.encode(passphrase));
    // RFC 2104: a key longer than the block is hashed first; a shorter one is
    // zero-padded. Ours is neither, normally, but the rule is the rule.
    if (key.length > 64) key = _sha256full(key);
    final ipad = Uint8List(64);
    final opad = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      final k = i < key.length ? key[i] : 0;
      ipad[i] = k ^ 0x36;
      opad[i] = k ^ 0x5c;
    }
    final w = Uint32List(64); // one scratch schedule for every compression
    final inner = _shaMidstate(ipad, w);
    final outer = _shaMidstate(opad, w);

    // dkLen 16 <= 32, so there is exactly one PBKDF2 block and its index is 1.
    final first = Uint8List(salt.length + 4)
      ..setRange(0, salt.length, salt)
      ..[salt.length + 3] = 1;
    var u = _shaFinish(outer, 64, _shaFinish(inner, 64, first, w), w);
    final acc = Uint8List.fromList(u);
    for (var i = 1; i < 100000; i++) {
      u = _shaFinish(outer, 64, _shaFinish(inner, 64, u, w), w);
      for (var j = 0; j < 32; j++) {
        acc[j] ^= u[j];
      }
    }
    return Uint8List.sublistView(acc, 0, 16);
  }

  // ── SHA-256, with the midstate left in our hands ──────────────────────
  //
  // package:crypto and pointycastle both hide the state behind a one-shot
  // digest, which is why neither can skip the pad blocks above (measured: 405
  // and 398 ms per derivation on a desktop, indistinguishable). This is the
  // ordinary algorithm, FIPS 180-4, with two entry points instead of one:
  // compress a block into a state, and finish a state that has already
  // absorbed some bytes.

  static const List<int> _shaK = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  static const List<int> _shaH0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  /// One 64-byte block of [b] from [off], compressed into [h].
  static void _shaBlock(Uint32List h, Uint8List b, int off, Uint32List w) {
    for (var i = 0; i < 16; i++) {
      final j = off + i * 4;
      w[i] = (b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3];
    }
    for (var i = 16; i < 64; i++) {
      final x = w[i - 15], y = w[i - 2];
      final s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
      final s1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = h[0], b2 = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var i = 0; i < 64; i++) {
      final s1 =
          ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
      final ch = (e & f) ^ (~e & g);
      final t1 = (hh + (s1 & 0xffffffff) + (ch & 0xffffffff) + _shaK[i] + w[i]) &
          0xffffffff;
      final s0 =
          ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
      final maj = (a & b2) ^ (a & c) ^ (b2 & c);
      final t2 = ((s0 & 0xffffffff) + (maj & 0xffffffff)) & 0xffffffff;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & 0xffffffff;
      d = c;
      c = b2;
      b2 = a;
      a = (t1 + t2) & 0xffffffff;
    }
    h[0] = h[0] + a;
    h[1] = h[1] + b2;
    h[2] = h[2] + c;
    h[3] = h[3] + d;
    h[4] = h[4] + e;
    h[5] = h[5] + f;
    h[6] = h[6] + g;
    h[7] = h[7] + hh;
  }

  /// The state after absorbing exactly one 64-byte [block] -- an HMAC pad.
  static Uint32List _shaMidstate(Uint8List block, Uint32List w) {
    final h = Uint32List.fromList(_shaH0);
    _shaBlock(h, block, 0, w);
    return h;
  }

  /// Finish a digest whose state [mid] has already absorbed [absorbed] bytes,
  /// over the remaining [msg]. [mid] is never mutated, so one midstate serves
  /// a hundred thousand iterations.
  static Uint8List _shaFinish(
      Uint32List mid, int absorbed, Uint8List msg, Uint32List w) {
    final h = Uint32List.fromList(mid);
    final total = absorbed + msg.length;
    // msg ‖ 0x80 ‖ zeros ‖ 64-bit big-endian bit count, to a block boundary.
    final tailLen = ((msg.length + 9 + 63) ~/ 64) * 64;
    final tail = Uint8List(tailLen)..setRange(0, msg.length, msg);
    tail[msg.length] = 0x80;
    final bits = total * 8;
    for (var i = 0; i < 8; i++) {
      tail[tailLen - 1 - i] = (bits >> (8 * i)) & 0xff;
    }
    for (var off = 0; off < tailLen; off += 64) {
      _shaBlock(h, tail, off, w);
    }
    final out = Uint8List(32);
    for (var i = 0; i < 8; i++) {
      out[i * 4] = (h[i] >> 24) & 0xff;
      out[i * 4 + 1] = (h[i] >> 16) & 0xff;
      out[i * 4 + 2] = (h[i] >> 8) & 0xff;
      out[i * 4 + 3] = h[i] & 0xff;
    }
    return out;
  }

  /// Plain SHA-256, for the over-long-key rule above.
  static Uint8List _sha256full(Uint8List msg) {
    final w = Uint32List(64);
    final h = Uint32List.fromList(_shaH0);
    var off = 0;
    for (; off + 64 <= msg.length; off += 64) {
      _shaBlock(h, msg, off, w);
    }
    return _shaFinish(h, off, Uint8List.sublistView(msg, off), w);
  }

  /// AES-128-CTR with a 16-byte IV = nonce(12) ‖ 32-bit big-endian counter
  /// from zero. CTR is symmetric, so this both encrypts and decrypts.
  static Uint8List _xrCipher(Uint8List key, Uint8List nonce, Uint8List data) {
    final iv = Uint8List(16)..setRange(0, 12, nonce); // low four bytes = 0
    final c = CTRStreamCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(key), iv));
    return c.process(data);
  }

  static String _b64urlEnc(Uint8List b) =>
      base64Url.encode(b).replaceAll('=', '');
  static Uint8List? _b64urlDec(String s) {
    try {
      final pad = (4 - s.length % 4) % 4;
      return base64Url.decode(s + ('=' * pad));
    } catch (_) {
      return null;
    }
  }

  /// Turn authored text with ((...)) marks into barred text plus the `xr:` blob
  /// (base64url, no padding). Chat only ever redacts the message body, so the
  /// bar runs here ARE the packet's runs, in order. Returns null when there is
  /// nothing marked. [nonce] is random unless supplied (tests pin it).
  static (String barred, String xr)? redact(String authored,
      {String passphrase = kXrDefaultPassphrase, Uint8List? nonce}) {
    final barred = StringBuffer();
    final secrets = <String>[];
    var i = 0;
    while (i < authored.length) {
      final open = authored.indexOf('((', i);
      if (open < 0) {
        barred.write(authored.substring(i));
        break;
      }
      final close = authored.indexOf('))', open + 2);
      if (close < 0) {
        barred.write(authored.substring(i));
        break;
      }
      barred.write(authored.substring(i, open));
      final secret = authored.substring(open + 2, close);
      barred.write(String.fromCharCode(_xrBarRune) * secret.runes.length);
      secrets.add(secret);
      i = close + 2;
    }
    if (secrets.isEmpty) return null;
    final nz = nonce ?? _randBytes(12);
    final plain = Uint8List.fromList(utf8.encode('->${secrets.join('\n')}'));
    final ct = _xrCipher(xrKey(passphrase, nz), nz, plain);
    return (barred.toString(), _b64urlEnc(Uint8List.fromList([...nz, ...ct])));
  }

  /// Decrypt an `xr:` blob to its hidden pieces (one per bar run, in packet
  /// order). Returns null on a wrong passphrase (no "->" sentinel) or a
  /// malformed blob. This is the RIGHT-KEY test; tampering is the signature's.
  static List<String>? xrSecrets(String xr, String passphrase) {
    final blob = _b64urlDec(xr);
    if (blob == null || blob.length < 12) return null;
    final nonce = Uint8List.fromList(blob.sublist(0, 12));
    final ct = Uint8List.fromList(blob.sublist(12));
    final pt = _xrCipher(xrKey(passphrase, nonce), nonce, ct);
    String text;
    try {
      text = utf8.decode(pt);
    } catch (_) {
      return null;
    }
    if (!text.startsWith('->')) return null;
    final rest = text.substring(2);
    return rest.isEmpty ? <String>[] : rest.split('\n');
  }

  /// Refill the █ runs in [barred] (a whole wire, or a single value) from the
  /// [xr] pieces, in order. Each piece must have EXACTLY its run's character
  /// count (a hundred-letter line cannot fill a three-bar hole), and every
  /// piece must be consumed. Returns the restored string, or null if the
  /// passphrase is wrong or the structure does not line up — in which case the
  /// caller keeps the bars.
  static String? restore(String barred, String xr, String passphrase) {
    final pieces = xrSecrets(xr, passphrase);
    if (pieces == null) return null;
    final runes = barred.runes.toList();
    final out = StringBuffer();
    var pi = 0, k = 0;
    while (k < runes.length) {
      if (runes[k] == _xrBarRune) {
        var len = 0;
        while (k < runes.length && runes[k] == _xrBarRune) {
          len++;
          k++;
        }
        if (pi >= pieces.length) return null;
        final piece = pieces[pi++];
        if (piece.runes.length != len) return null;
        out.write(piece);
      } else {
        out.writeCharCode(runes[k]);
        k++;
      }
    }
    if (pi != pieces.length) return null; // more pieces than holes
    return out.toString();
  }

  /// True when [text] carries at least one redaction bar.
  static bool hasBars(String text) => text.contains('█');

}
