/*
 * coin_ec — secp256k1 point arithmetic for the participation coin's bearer
 * tokens (BDHKE + DLEQ). NostrCrypto keeps its EC helpers private, so this is a
 * small, self-contained wrapper over pointycastle's secp256k1 curve exposing the
 * operations Chaumian ecash needs: scalar/point multiply, point add/sub/negate,
 * compressed point (de)serialization, hash-to-curve and hash-to-scalar.
 *
 * Pure/headless: pointycastle + crypto + dart:typed_data only. No app deps.
 *
 * Conventions: scalars are BigInt mod n; points are pointycastle ECPoint;
 * the on-wire encoding of a point is the 33-byte SEC1 compressed form.
 */
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

/// Domain separator for hash-to-curve (matches the Cashu NUT-00 tag so our
/// tokens use the same well-reviewed mapping).
const String _hashToCurveDomain = 'Secp256k1_HashToCurve_Cashu_';

class CoinEc {
  CoinEc._();

  static final ECDomainParameters domain = ECCurve_secp256k1();

  /// Group order.
  static BigInt get n => domain.n;

  /// Generator point.
  static ECPoint get G => domain.G;

  /// Field prime p of secp256k1 (y^2 = x^3 + 7 mod p).
  static final BigInt p = BigInt.parse(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
      radix: 16);

  static final Random _rng = Random.secure();

  // ── scalars ────────────────────────────────────────────────────────────────

  /// A uniformly random non-zero scalar in [1, n-1].
  static BigInt randomScalar() {
    while (true) {
      final b = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        b[i] = _rng.nextInt(256);
      }
      final s = bytesToBigInt(b) % n;
      if (s != BigInt.zero) return s;
    }
  }

  static BigInt bytesToBigInt(Uint8List bytes) {
    var r = BigInt.zero;
    for (final b in bytes) {
      r = (r << 8) | BigInt.from(b);
    }
    return r;
  }

  static Uint8List bigIntToBytes(BigInt v, [int length = 32]) {
    final out = Uint8List(length);
    var t = v;
    for (var i = length - 1; i >= 0; i--) {
      out[i] = (t & BigInt.from(0xff)).toInt();
      t = t >> 8;
    }
    return out;
  }

  // ── points ───────────────────────────────────────────────────────────────

  static ECPoint mulG(BigInt scalar) => (G * scalar)!;

  static ECPoint mul(ECPoint point, BigInt scalar) => (point * scalar)!;

  static ECPoint add(ECPoint a, ECPoint b) => (a + b)!;

  /// -P (negate the y coordinate mod p).
  static ECPoint negate(ECPoint point) {
    final x = point.x!.toBigInteger()!;
    final y = point.y!.toBigInteger()!;
    return domain.curve.createPoint(x, (p - y) % p);
  }

  static ECPoint sub(ECPoint a, ECPoint b) => add(a, negate(b));

  /// 33-byte SEC1 compressed encoding (0x02/0x03 || x).
  static Uint8List encodePoint(ECPoint point) => point.getEncoded(true);

  /// Constant-shape equality via compressed encoding (pointycastle's ECPoint
  /// does not reliably override ==).
  static bool pointEq(ECPoint a, ECPoint b) {
    final ea = encodePoint(a);
    final eb = encodePoint(b);
    if (ea.length != eb.length) return false;
    for (var i = 0; i < ea.length; i++) {
      if (ea[i] != eb[i]) return false;
    }
    return true;
  }

  /// Parse a 33-byte compressed point. Returns null if invalid/not on curve.
  static ECPoint? decodePoint(Uint8List bytes) {
    try {
      final pt = domain.curve.decodePoint(bytes);
      if (pt == null || pt.isInfinity) return null;
      return pt;
    } catch (_) {
      return null;
    }
  }

  // ── hashing ────────────────────────────────────────────────────────────────

  static Uint8List _sha256(List<int> data) =>
      Uint8List.fromList(sha256.convert(data).bytes);

  /// Deterministically map a message to a curve point (try-and-increment over a
  /// 4-byte counter, lifting the hash as an x-coordinate). Domain-separated.
  static ECPoint hashToCurve(Uint8List message) {
    final msgHash = _sha256([..._domainPrefix, ...message]);
    for (var counter = 0; counter < 0x10000; counter++) {
      final c = Uint8List(4)
        ..buffer.asByteData().setUint32(0, counter, Endian.little);
      final hash = _sha256([...msgHash, ...c]);
      // Try as a compressed point with even-y prefix (0x02).
      final candidate = decodePoint(Uint8List.fromList([0x02, ...hash]));
      if (candidate != null) return candidate;
    }
    // Astronomically unlikely (~2^-65536); surfaces a real bug if it ever fires.
    throw StateError('hashToCurve: no valid point found');
  }

  static final List<int> _domainPrefix = _hashToCurveDomain.codeUnits;

  /// Hash a sequence of points to a scalar mod n (DLEQ Fiat-Shamir challenge).
  static BigInt hashToScalar(List<ECPoint> points) {
    final buf = <int>[];
    for (final pt in points) {
      buf.addAll(encodePoint(pt));
    }
    return bytesToBigInt(_sha256(buf)) % n;
  }
}
