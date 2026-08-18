/*
 * mint — the administrator-run mint for one coin: holds the SECRET keyset and a
 * spent-secret index, and performs the operations only the key-holder can do.
 *
 *  - signIssue: blind-sign a wallet's blinded message (used when granting/faucet
 *    issuance hands fresh bearer tokens to a user who blinded a secret).
 *  - redeem: verify a bearer Proof (C == k*Y) and burn its secret.
 *  - swap: atomically melt input proofs and mint new blinded outputs of equal
 *    value — this is exact CHANGE-MAKING (split a big token into small ones, or
 *    merge), the piece the wallet/postage paths need so a hand-off need not
 *    overpay.
 *
 * A swap that fails validation records nothing (atomic). Pure/headless:
 * bearer_token + coin_keyset + coin_ec.
 */
import 'package:pointycastle/export.dart';

import 'bearer_token.dart';
import 'coin_keyset.dart';

/// A blinded output the wallet wants signed: its denomination + B_ (Y + r*G).
class BlindedOutput {
  final int amount;
  final ECPoint blinded;
  const BlindedOutput(this.amount, this.blinded);

  /// Convenience: from a wallet's BlindContext.
  factory BlindedOutput.of(BlindContext ctx) =>
      BlindedOutput(ctx.amount, ctx.blinded);
}

class Mint {
  final CoinMintKeys keys;
  final Set<String> _spent = {}; // burned token secrets

  Mint(this.keys);

  String get coinId => keys.coinId;
  String get keysetId => keys.keysetId;
  CoinKeyset get publicKeyset => keys.public;

  bool isSpent(String secretHex) => _spent.contains(secretHex);

  /// Blind-sign [blinded] (B_) for [amount]. Returns null if the mint has no key
  /// for that denomination.
  BlindSignature? signIssue(int amount, ECPoint blinded) {
    final k = keys.privFor(amount);
    if (k == null) return null;
    return Bdhke.mintSign(amount, keysetId, k, blinded);
  }

  /// Verify and burn a bearer [proof]. Returns false (recording nothing) if the
  /// token is for another keyset, already spent, an unknown denomination, or
  /// forged.
  bool redeem(Proof proof) {
    if (!_validUnspent(proof)) return false;
    _spent.add(proof.secretHex);
    return true;
  }

  /// Atomically melt [inputs] and mint [outputs] of EQUAL total value. Verifies
  /// every input (and forbids duplicates), checks value conservation, then burns
  /// the inputs and blind-signs the outputs. Returns the signatures aligned with
  /// [outputs], or null if anything is invalid (nothing is recorded on failure).
  List<BlindSignature>? swap(List<Proof> inputs, List<BlindedOutput> outputs) {
    final seen = <String>{};
    var inSum = 0;
    for (final p in inputs) {
      if (!seen.add(p.secretHex)) return null; // duplicate input in this swap
      if (!_validUnspent(p)) return null;
      inSum += p.amount;
    }
    var outSum = 0;
    for (final o in outputs) {
      if (keys.privFor(o.amount) == null) return null; // unknown denomination
      outSum += o.amount;
    }
    if (outSum != inSum) return null; // value must be conserved (no fee in v1)

    // All valid: commit.
    for (final p in inputs) {
      _spent.add(p.secretHex);
    }
    return [
      for (final o in outputs)
        Bdhke.mintSign(o.amount, keysetId, keys.privFor(o.amount)!, o.blinded)
    ];
  }

  bool _validUnspent(Proof proof) {
    if (proof.keysetId != keysetId) return false;
    if (_spent.contains(proof.secretHex)) return false;
    final k = keys.privFor(proof.amount);
    if (k == null) return false;
    return Bdhke.mintVerify(proof, k);
  }
}
