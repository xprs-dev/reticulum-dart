/*
 * coin_keyset — the mint keys of a participation coin.
 *
 * A coin is identified by its administrator's x-only pubkey (coinId / npub). The
 * administrator runs the mint, which holds a keyset: one secp256k1 keypair per
 * denomination (powers of two, Cashu-style) so a blind signature cryptographically
 * binds the token's amount. The PUBLIC half (CoinKeyset: amount -> public point)
 * is what gets published in the authority log and shipped to wallets; the SECRET
 * half (CoinMintKeys: amount -> private scalar) never leaves the mint.
 *
 * Keys are derived deterministically from a seed so the mint can be re-created
 * from backup, and the keysetId is a hash of the public keys so a wallet can pin
 * exactly which keys it trusts.
 *
 * Pure/headless: coin_ec + crypto + hex only.
 */
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

import 'coin_ec.dart';

/// Default denominations: powers of two 2^0 .. 2^20 (1 .. 1_048_576).
const int kDefaultMaxDenomExp = 20;

List<int> denominations({int maxExp = kDefaultMaxDenomExp}) =>
    [for (var e = 0; e <= maxExp; e++) 1 << e];

/// Greedy split of [amount] into available power-of-two denominations.
List<int> splitAmount(int amount, {int maxExp = kDefaultMaxDenomExp}) {
  final out = <int>[];
  var remaining = amount;
  for (var e = maxExp; e >= 0 && remaining > 0; e--) {
    final d = 1 << e;
    while (remaining >= d) {
      out.add(d);
      remaining -= d;
    }
  }
  return out;
}

/// The PUBLIC keyset a wallet/verifier uses: amount -> mint public key.
class CoinKeyset {
  final String coinId; // administrator x-only pubkey hex (owns this coin)
  final String keysetId; // pinned hash of the public keys (versioned)
  final Map<int, ECPoint> keys;

  CoinKeyset(this.coinId, this.keysetId, this.keys);

  ECPoint? keyFor(int amount) => keys[amount];

  Map<String, dynamic> toJson() => {
        'coinId': coinId,
        'keysetId': keysetId,
        'keys': {
          for (final e in keys.entries)
            e.key.toString(): HEX.encode(CoinEc.encodePoint(e.value)),
        },
      };

  static CoinKeyset? fromJson(Object? o) {
    if (o is! Map) return null;
    final coinId = o['coinId'];
    final keysetId = o['keysetId'];
    final keys = o['keys'];
    if (coinId is! String || keysetId is! String || keys is! Map) return null;
    final parsed = <int, ECPoint>{};
    for (final e in keys.entries) {
      final amount = int.tryParse(e.key.toString());
      final pt = e.value is String
          ? CoinEc.decodePoint(Uint8List.fromList(HEX.decode(e.value as String)))
          : null;
      if (amount == null || pt == null) return null;
      parsed[amount] = pt;
    }
    return CoinKeyset(coinId, keysetId, parsed);
  }
}

/// The SECRET keyset held only by the mint: amount -> private scalar.
class CoinMintKeys {
  final String coinId;
  final String keysetId;
  final Map<int, BigInt> priv;
  final CoinKeyset public;

  CoinMintKeys._(this.coinId, this.keysetId, this.priv, this.public);

  BigInt? privFor(int amount) => priv[amount];

  /// Derive the mint keyset deterministically from a [seedHex] (the
  /// administrator's secret coin seed) for the coin owned by [coinId].
  factory CoinMintKeys.derive(String coinId, String seedHex,
      {int maxExp = kDefaultMaxDenomExp}) {
    final seed = Uint8List.fromList(HEX.decode(seedHex));
    final priv = <int, BigInt>{};
    final pub = <int, ECPoint>{};
    for (final amount in denominations(maxExp: maxExp)) {
      final k = _deriveScalar(seed, amount);
      priv[amount] = k;
      pub[amount] = CoinEc.mulG(k);
    }
    final keysetId = _keysetId(pub);
    return CoinMintKeys._(
        coinId, keysetId, priv, CoinKeyset(coinId, keysetId, pub));
  }

  static BigInt _deriveScalar(Uint8List seed, int amount) {
    var counter = 0;
    while (true) {
      final input = <int>[
        ...seed,
        ...'/$amount/$counter'.codeUnits,
      ];
      final h = Uint8List.fromList(sha256.convert(input).bytes);
      final s = CoinEc.bytesToBigInt(h) % CoinEc.n;
      if (s != BigInt.zero) return s;
      counter++;
    }
  }
}

/// Keyset id: version byte '00' + first 14 hex chars of sha256 over the sorted
/// (amount, compressed-pubkey) pairs. Pins exactly which public keys a wallet
/// trusts.
String _keysetId(Map<int, ECPoint> pub) {
  final amounts = pub.keys.toList()..sort();
  final buf = <int>[];
  for (final a in amounts) {
    buf.addAll(CoinEc.bigIntToBytes(BigInt.from(a), 8));
    buf.addAll(CoinEc.encodePoint(pub[a]!));
  }
  final h = HEX.encode(sha256.convert(buf).bytes);
  return '00${h.substring(0, 14)}';
}
