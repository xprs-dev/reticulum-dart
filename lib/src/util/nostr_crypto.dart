/*
 * Copyright (c) XPRS
 * License: Apache-2.0
 *
 * NOSTR Cryptography Implementation
 * Implements NIP-01 compatible signing using BIP-340 Schnorr signatures
 *
 * Vendored from XPRS/lib/util/nostr_crypto.dart — keep in sync
 * manually until a shared package lands.
 */

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:bech32/bech32.dart';
import 'package:hex/hex.dart';

/// NOSTR cryptographic operations
class NostrCrypto {
  static final _secureRandom = SecureRandom('Fortuna')
    ..seed(KeyParameter(
      Uint8List.fromList(List.generate(32, (_) => Random.secure().nextInt(256))),
    ));

  /// Generate a new secp256k1 key pair
  static NostrKeyPair generateKeyPair() {
    final keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());
    final generator = ECKeyGenerator()
      ..init(ParametersWithRandom(keyParams, _secureRandom));

    final keyPair = generator.generateKeyPair();
    final privateKey = keyPair.privateKey as ECPrivateKey;
    final publicKey = keyPair.publicKey as ECPublicKey;

    // Get raw bytes
    final privateKeyBytes = _bigIntToBytes(privateKey.d!, 32);

    // For Schnorr (BIP-340), we use x-only public key (32 bytes)
    final publicKeyBytes = _bigIntToBytes(publicKey.Q!.x!.toBigInteger()!, 32);

    return NostrKeyPair(
      privateKeyHex: HEX.encode(privateKeyBytes),
      publicKeyHex: HEX.encode(publicKeyBytes),
    );
  }

  /// Derive public key from private key
  static String derivePublicKey(String privateKeyHex) {
    final privateKeyBytes = HEX.decode(privateKeyHex);
    final d = _bytesToBigInt(Uint8List.fromList(privateKeyBytes));

    final curve = ECCurve_secp256k1();
    final Q = curve.G * d;

    // X-only public key for BIP-340
    final publicKeyBytes = _bigIntToBytes(Q!.x!.toBigInteger()!, 32);
    return HEX.encode(publicKeyBytes);
  }

  /// Sign a message using BIP-340 Schnorr signature
  /// Returns 64-byte signature as hex string
  static String schnorrSign(String messageHex, String privateKeyHex) {
    final messageBytes = HEX.decode(messageHex);
    final privateKeyBytes = HEX.decode(privateKeyHex);

    // BIP-340 Schnorr signature implementation
    final d = _bytesToBigInt(Uint8List.fromList(privateKeyBytes));
    final curve = ECCurve_secp256k1();
    final n = curve.n;
    final G = curve.G;

    // Get public key point
    final P = G * d;
    final px = _bigIntToBytes(P!.x!.toBigInteger()!, 32);

    // If P.y is odd, negate d
    var dPrime = d;
    if (P.y!.toBigInteger()!.isOdd) {
      dPrime = n - d;
    }

    // Generate deterministic nonce using RFC 6979 style
    final auxRand = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      auxRand[i] = Random.secure().nextInt(256);
    }

    // t = bytes(d') xor tagged_hash("BIP0340/aux", auxRand)
    final dPrimeBytes = _bigIntToBytes(dPrime, 32);
    final auxHash = _taggedHash('BIP0340/aux', auxRand);
    final t = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      t[i] = dPrimeBytes[i] ^ auxHash[i];
    }

    // k' = tagged_hash("BIP0340/nonce", t || bytes(P) || m) mod n
    final nonceInput = Uint8List.fromList([...t, ...px, ...messageBytes]);
    final kPrimeHash = _taggedHash('BIP0340/nonce', nonceInput);
    var kPrime = _bytesToBigInt(kPrimeHash) % n;

    if (kPrime == BigInt.zero) {
      throw Exception('Invalid nonce generated');
    }

    // R = k' * G
    final R = G * kPrime;
    final rx = _bigIntToBytes(R!.x!.toBigInteger()!, 32);

    // If R.y is odd, negate k'
    if (R.y!.toBigInteger()!.isOdd) {
      kPrime = n - kPrime;
    }

    // e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m) mod n
    final challengeInput = Uint8List.fromList([...rx, ...px, ...messageBytes]);
    final eHash = _taggedHash('BIP0340/challenge', challengeInput);
    final e = _bytesToBigInt(eHash) % n;

    // s = (k' + e * d') mod n
    final s = (kPrime + e * dPrime) % n;
    final sBytes = _bigIntToBytes(s, 32);

    // Signature is R.x || s (64 bytes)
    final signature = Uint8List.fromList([...rx, ...sBytes]);
    return HEX.encode(signature);
  }

  /// Verify a BIP-340 Schnorr signature
  static bool schnorrVerify(String messageHex, String signatureHex, String publicKeyHex) {
    try {
      final messageBytes = HEX.decode(messageHex);
      final sigBytes = HEX.decode(signatureHex);
      final pubKeyBytes = HEX.decode(publicKeyHex);

      if (sigBytes.length != 64 || pubKeyBytes.length != 32) {
        return false;
      }

      final curve = ECCurve_secp256k1();
      final n = curve.n;
      final G = curve.G;
      // secp256k1 field prime
      final p = BigInt.parse('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', radix: 16);

      // Extract r and s from signature
      final r = _bytesToBigInt(Uint8List.fromList(sigBytes.sublist(0, 32)));
      final s = _bytesToBigInt(Uint8List.fromList(sigBytes.sublist(32, 64)));

      // Check r and s are in valid range
      if (r >= p || s >= n) {
        return false;
      }

      // Compute y from x (lift_x)
      final px = _bytesToBigInt(Uint8List.fromList(pubKeyBytes));
      final P = _liftX(px, curve);
      if (P == null) {
        return false;
      }

      // e = tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || m) mod n
      final rx = _bigIntToBytes(r, 32);
      final pxBytes = _bigIntToBytes(px, 32);
      final challengeInput = Uint8List.fromList([...rx, ...pxBytes, ...messageBytes]);
      final eHash = _taggedHash('BIP0340/challenge', challengeInput);
      final e = _bytesToBigInt(eHash) % n;

      // R = s*G - e*P
      final sG = G * s;
      final eP = P * e;
      // Negate eP by negating y coordinate
      final negY = p - eP!.y!.toBigInteger()!;
      final negEP = curve.curve.createPoint(eP.x!.toBigInteger()!, negY);
      final R = sG! + negEP;

      if (R == null || R.isInfinity) {
        return false;
      }

      // Check R.y is even
      if (R.y!.toBigInteger()!.isOdd) {
        return false;
      }

      // Check R.x == r
      return R.x!.toBigInteger() == r;
    } catch (e) {
      return false;
    }
  }

  /// Encode private key to nsec (bech32)
  static String encodeNsec(String privateKeyHex) {
    final bytes = HEX.decode(privateKeyHex);
    final data = _convertBits(Uint8List.fromList(bytes), 8, 5, true);
    final bech32Data = Bech32('nsec', data);
    return const Bech32Codec().encode(bech32Data);
  }

  /// Decode nsec to private key hex
  static String decodeNsec(String nsec) {
    final bech32Data = const Bech32Codec().decode(nsec);
    if (bech32Data.hrp != 'nsec') {
      throw FormatException('Invalid nsec prefix');
    }
    final bytes = _convertBits(Uint8List.fromList(bech32Data.data), 5, 8, false);
    return HEX.encode(bytes);
  }

  /// Encode public key to npub (bech32)
  static String encodeNpub(String publicKeyHex) {
    final bytes = HEX.decode(publicKeyHex);
    final data = _convertBits(Uint8List.fromList(bytes), 8, 5, true);
    final bech32Data = Bech32('npub', data);
    return const Bech32Codec().encode(bech32Data);
  }

  /// Decode npub to public key hex
  static String decodeNpub(String npub) {
    final bech32Data = const Bech32Codec().decode(npub);
    if (bech32Data.hrp != 'npub') {
      throw FormatException('Invalid npub prefix');
    }
    final bytes = _convertBits(Uint8List.fromList(bech32Data.data), 5, 8, false);
    return HEX.encode(bytes);
  }

  /// Shortest and longest callsign a holder may derive from their own key.
  static const int kMinCallsignLength = 2;
  static const int kMaxCallsignLength = 5;

  /// The default, and what every callsign in the field is today.
  static const int kDefaultCallsignLength = 4;

  /// Derive callsign from npub
  ///
  /// Format: the first [length] characters after 'npub1' (uppercased). The
  /// holder chooses how much of their own key to show, between
  /// [kMinCallsignLength] and [kMaxCallsignLength]; four is the default and
  /// leaves every existing caller returning exactly what it returned before.
  ///
  /// Shorter is weaker, and knowingly so: two characters is 1024 values, so
  /// two people collide after about forty of them and anyone can grind a
  /// matching key in about a thousand tries. A callsign is a label, not an
  /// identity (spec section 3) -- anything that must be unforgeable verifies a
  /// signature against the full key.
  static String deriveCallsign(String publicKeyHex,
      {int length = kDefaultCallsignLength}) {
    if (length < kMinCallsignLength || length > kMaxCallsignLength) {
      throw ArgumentError.value(length, 'length',
          'callsign length must be $kMinCallsignLength..$kMaxCallsignLength');
    }
    // Encode to npub first, then extract characters
    final npub = encodeNpub(publicKeyHex);
    // Return the first `length` chars after 'npub1'
    return npub.substring(5, 5 + length).toUpperCase();
  }

  /// The person, with any device suffix removed.
  ///
  /// `X1ABCD-1` and `X1ABCD-2` are two devices of one operator (spec section
  /// 3.1), so everything keyed on a *person* -- a thread, a reputation, a
  /// block, a follow -- keys on what this returns.
  static String bareCallsign(String callsign) =>
      callsign.trim().toUpperCase().split('-').first;

  /// Whether [callsign] could have been derived from [publicKeyHex].
  ///
  /// Strips the device suffix first, then the `X1`/`X3`/`X4`/`X5` prefix, and
  /// checks the remainder against the key's bech32 encoding at that length.
  ///
  /// **This answers "could this key produce this label", not "is this the
  /// holder's callsign".** Given only a callsign and a key there is no way to
  /// tell which length the holder chose, so all four truncations of one key
  /// pass: a holder announcing `X1ABCD` also satisfies `X1AB` here.
  ///
  /// What makes a callsign canonical is the signed identity announcement that
  /// declares it. Once that is verified, callsigns are compared as whole
  /// strings -- never with [String.startsWith] -- and that comparison, not
  /// this function, is what stops one person from wearing four names.
  ///
  /// Returns false for a callsign that is not self-derived -- a licensed
  /// `CT1ABC-9` or `G0XYZ/P` carries no `X1/X3/X4/X5` prefix and is bound to a
  /// key by other means (spec section 9.4.2), so this test does not apply.
  static bool callsignMatchesKey(String callsign, String publicKeyHex) {
    final bare = bareCallsign(callsign);
    if (bare.length < 2) return false;
    final prefix = bare.substring(0, 2);
    if (prefix != 'X1' &&
        prefix != 'X2' &&
        prefix != 'X3' &&
        prefix != 'X4' &&
        prefix != 'X5') {
      return false;
    }
    final chars = bare.substring(2);
    if (chars.length < kMinCallsignLength ||
        chars.length > kMaxCallsignLength) {
      return false;
    }
    try {
      return deriveCallsign(publicKeyHex, length: chars.length) == chars;
    } catch (_) {
      return false;
    }
  }

  /// Create SHA256 hash of data
  static String sha256Hash(String data) {
    final bytes = utf8.encode(data);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  /// Create SHA256 hash of bytes
  static Uint8List sha256Bytes(Uint8List data) {
    final digest = sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  // === Private helper methods ===

  /// Tagged hash as per BIP-340
  static Uint8List _taggedHash(String tag, Uint8List data) {
    final tagHash = sha256.convert(utf8.encode(tag)).bytes;
    final input = Uint8List.fromList([...tagHash, ...tagHash, ...data]);
    return Uint8List.fromList(sha256.convert(input).bytes);
  }

  /// Convert BigInt to fixed-size bytes
  static Uint8List _bigIntToBytes(BigInt value, int length) {
    final bytes = Uint8List(length);
    var temp = value;
    for (var i = length - 1; i >= 0; i--) {
      bytes[i] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }
    return bytes;
  }

  /// Convert bytes to BigInt
  static BigInt _bytesToBigInt(Uint8List bytes) {
    var result = BigInt.zero;
    for (final byte in bytes) {
      result = (result << 8) | BigInt.from(byte);
    }
    return result;
  }

  /// Lift x-coordinate to curve point (BIP-340)
  static ECPoint? _liftX(BigInt x, ECDomainParameters curve) {
    // secp256k1 field prime
    final p = BigInt.parse('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', radix: 16);
    if (x >= p) return null;

    // y² = x³ + 7 (mod p) for secp256k1
    final ySq = (x.modPow(BigInt.from(3), p) + BigInt.from(7)) % p;

    // y = y²^((p+1)/4) mod p
    final y = ySq.modPow((p + BigInt.one) ~/ BigInt.from(4), p);

    // Verify y² = ySq
    if ((y * y) % p != ySq) return null;

    // Return point with even y
    final yFinal = y.isEven ? y : p - y;

    return curve.curve.createPoint(x, yFinal);
  }

  /// Convert bits between bases (for bech32)
  static Uint8List _convertBits(Uint8List data, int fromBits, int toBits, bool pad) {
    var acc = 0;
    var bits = 0;
    final result = <int>[];
    final maxv = (1 << toBits) - 1;

    for (final value in data) {
      acc = (acc << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        result.add((acc >> bits) & maxv);
      }
    }

    if (pad) {
      if (bits > 0) {
        result.add((acc << (toBits - bits)) & maxv);
      }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
      throw FormatException('Invalid bit conversion');
    }

    return Uint8List.fromList(result);
  }
}

/// NOSTR key pair
class NostrKeyPair {
  final String privateKeyHex;
  final String publicKeyHex;

  NostrKeyPair({
    required this.privateKeyHex,
    required this.publicKeyHex,
  });

  /// Get nsec (bech32 encoded private key)
  String get nsec => NostrCrypto.encodeNsec(privateKeyHex);

  /// Get npub (bech32 encoded public key)
  String get npub => NostrCrypto.encodeNpub(publicKeyHex);

  /// Get derived callsign (X1 + first 4 chars of npub after 'npub1')
  String get callsign => callsignOfLength();

  /// The same callsign at a chosen length, 2 to 5 (spec section 3).
  String callsignOfLength(
          {int length = NostrCrypto.kDefaultCallsignLength}) =>
      'X1${NostrCrypto.deriveCallsign(publicKeyHex, length: length)}';
}
