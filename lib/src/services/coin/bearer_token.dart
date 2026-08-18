/*
 * bearer_token — Chaumian ecash for the participation coin (BDHKE + DLEQ).
 *
 * This is the offline-transferable money primitive. A wallet blinds a random
 * secret, the mint blind-signs it (without learning the secret), the wallet
 * unblinds to a bearer Proof, and the Proof can be handed to anyone fully
 * offline. The recipient verifies it with NO network using the mint's published
 * keyset plus the DLEQ proof carried in the token (this is the "run checks
 * offline to others" property the user wanted from Cashu). Double-spend is
 * caught later when a mint/ATM sees the same secret twice.
 *
 * BDHKE (Wallet=Alice, Mint=Bob, mint key k, K = k*G):
 *   blind:    Y = hashToCurve(secret); B_ = Y + r*G          (r = blinding scalar)
 *   sign:     C_ = k*B_   (+ DLEQ proving the same k as in K)
 *   unblind:  C = C_ - r*K = k*Y                              (bearer Proof = secret,C)
 *   redeem:   mint checks C == k*Y     (knows k)
 *   offline:  verifier re-blinds with r and checks the DLEQ against K (no k needed)
 *
 * Pure/headless: coin_ec + coin_keyset + hex + dart:convert.
 */
import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

import 'coin_ec.dart';

/// What the wallet keeps locally after blinding, needed to unblind the mint's
/// reply. Not shared.
class BlindContext {
  final int amount;
  final String keysetId;
  final String secretHex; // 32-byte random secret x
  final BigInt r; // blinding scalar
  final ECPoint blinded; // B_

  const BlindContext(
      this.amount, this.keysetId, this.secretHex, this.r, this.blinded);

  String get blindedHex => HEX.encode(CoinEc.encodePoint(blinded));
}

/// The mint's blind signature over B_, with a DLEQ proof tying it to K.
class BlindSignature {
  final int amount;
  final String keysetId;
  final ECPoint cBlinded; // C_
  final BigInt e; // DLEQ challenge
  final BigInt s; // DLEQ response

  const BlindSignature(
      this.amount, this.keysetId, this.cBlinded, this.e, this.s);
}

/// A spendable bearer token. Carries the blinding scalar [rHex] and the DLEQ
/// (e,s) so a third party can verify authenticity offline.
class Proof {
  final int amount;
  final String keysetId;
  final String secretHex; // x
  final String cHex; // C = k*Y (compressed)
  final String rHex; // blinding scalar (for offline DLEQ re-blinding)
  final BigInt e;
  final BigInt s;

  const Proof(this.amount, this.keysetId, this.secretHex, this.cHex, this.rHex,
      this.e, this.s);

  Map<String, dynamic> toJson() => {
        'a': amount,
        'id': keysetId,
        'secret': secretHex,
        'C': cHex,
        'r': rHex,
        'e': HEX.encode(CoinEc.bigIntToBytes(e)),
        's': HEX.encode(CoinEc.bigIntToBytes(s)),
      };

  static Proof? fromJson(Object? o) {
    if (o is! Map) return null;
    final a = o['a'];
    final id = o['id'];
    final secret = o['secret'];
    final c = o['C'];
    final r = o['r'];
    final e = o['e'];
    final s = o['s'];
    if (a is! int ||
        id is! String ||
        secret is! String ||
        c is! String ||
        r is! String ||
        e is! String ||
        s is! String) {
      return null;
    }
    return Proof(
        a,
        id,
        secret,
        c,
        r,
        CoinEc.bytesToBigInt(Uint8List.fromList(HEX.decode(e))),
        CoinEc.bytesToBigInt(Uint8List.fromList(HEX.decode(s))));
  }
}

/// A transferable bundle of proofs for one coin. `coin1...` base64url token.
class BearerToken {
  final String coinId;
  final List<Proof> proofs;

  const BearerToken(this.coinId, this.proofs);

  int get amount => proofs.fold(0, (sum, p) => sum + p.amount);

  String encode() {
    final json = jsonEncode({
      'coin': coinId,
      'proofs': [for (final p in proofs) p.toJson()],
    });
    return 'coin1${base64Url.encode(utf8.encode(json))}';
  }

  static BearerToken? decode(String token) {
    if (!token.startsWith('coin1')) return null;
    try {
      final json = jsonDecode(utf8.decode(base64Url.decode(token.substring(5))));
      if (json is! Map) return null;
      final coin = json['coin'];
      final list = json['proofs'];
      if (coin is! String || list is! List) return null;
      final proofs = <Proof>[];
      for (final e in list) {
        final p = Proof.fromJson(e);
        if (p == null) return null;
        proofs.add(p);
      }
      return BearerToken(coin, proofs);
    } catch (_) {
      return null;
    }
  }
}

class Bdhke {
  Bdhke._();

  /// Wallet step 1: blind a fresh random secret for [amount].
  static BlindContext blind(int amount, String keysetId) {
    final secret = CoinEc.bigIntToBytes(CoinEc.randomScalar());
    return blindSecret(amount, keysetId, HEX.encode(secret));
  }

  /// Blind a specific [secretHex] (deterministic; used by tests/recovery).
  static BlindContext blindSecret(int amount, String keysetId, String secretHex) {
    final y = CoinEc.hashToCurve(Uint8List.fromList(HEX.decode(secretHex)));
    final r = CoinEc.randomScalar();
    final bBlinded = CoinEc.add(y, CoinEc.mulG(r)); // B_ = Y + r*G
    return BlindContext(amount, keysetId, secretHex, r, bBlinded);
  }

  /// Mint step: blind-sign B_ with the per-amount private key [k], attaching a
  /// DLEQ proof that the same k underlies the published K = k*G.
  static BlindSignature mintSign(
      int amount, String keysetId, BigInt k, ECPoint bBlinded) {
    final cBlinded = CoinEc.mul(bBlinded, k); // C_ = k*B_
    final kK = CoinEc.mulG(k); // K = k*G
    // DLEQ (e,s): prove log_G(K) == log_B_(C_).
    final rd = CoinEc.randomScalar();
    final r1 = CoinEc.mulG(rd); // R1 = rd*G
    final r2 = CoinEc.mul(bBlinded, rd); // R2 = rd*B_
    final e = CoinEc.hashToScalar([r1, r2, kK, cBlinded]);
    final s = (rd + e * k) % CoinEc.n;
    return BlindSignature(amount, keysetId, cBlinded, e, s);
  }

  /// Wallet step 2: unblind the mint's signature into a bearer [Proof].
  /// [mintPub] is K for this amount (from the published keyset).
  static Proof unblind(BlindContext ctx, BlindSignature sig, ECPoint mintPub) {
    // C = C_ - r*K
    final c = CoinEc.sub(sig.cBlinded, CoinEc.mul(mintPub, ctx.r));
    return Proof(
      ctx.amount,
      ctx.keysetId,
      ctx.secretHex,
      HEX.encode(CoinEc.encodePoint(c)),
      HEX.encode(CoinEc.bigIntToBytes(ctx.r)),
      sig.e,
      sig.s,
    );
  }

  /// Offline third-party verification: recompute the blinded values from the
  /// proof's secret + blinding scalar and check the DLEQ against the published
  /// key [mintPub] (K). No private key, no network.
  static bool verifyOffline(Proof proof, ECPoint mintPub) {
    try {
      final c = CoinEc.decodePoint(Uint8List.fromList(HEX.decode(proof.cHex)));
      if (c == null) return false;
      final r =
          CoinEc.bytesToBigInt(Uint8List.fromList(HEX.decode(proof.rHex)));
      final y = CoinEc.hashToCurve(
          Uint8List.fromList(HEX.decode(proof.secretHex)));
      // Reconstruct the blinded pair the mint actually signed.
      final cBlinded = CoinEc.add(c, CoinEc.mul(mintPub, r)); // C_ = C + r*K
      final bBlinded = CoinEc.add(y, CoinEc.mulG(r)); // B_ = Y + r*G
      // DLEQ check: R1 = s*G - e*K, R2 = s*B_ - e*C_.
      final r1 = CoinEc.sub(CoinEc.mulG(proof.s), CoinEc.mul(mintPub, proof.e));
      final r2 =
          CoinEc.sub(CoinEc.mul(bBlinded, proof.s), CoinEc.mul(cBlinded, proof.e));
      final expected = CoinEc.hashToScalar([r1, r2, mintPub, cBlinded]);
      return expected == proof.e;
    } catch (_) {
      return false;
    }
  }

  /// Mint-side redemption check: with the private key [k] for this amount,
  /// verify C == k*Y. Used by the mint/ATM when settling a token.
  static bool mintVerify(Proof proof, BigInt k) {
    try {
      final c = CoinEc.decodePoint(Uint8List.fromList(HEX.decode(proof.cHex)));
      if (c == null) return false;
      final y = CoinEc.hashToCurve(
          Uint8List.fromList(HEX.decode(proof.secretHex)));
      final expected = CoinEc.mul(y, k); // k*Y
      return CoinEc.pointEq(expected, c);
    } catch (_) {
      return false;
    }
  }
}
