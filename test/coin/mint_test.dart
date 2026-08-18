import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/mint.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  Mint freshMint() => Mint(CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8));

  // Issue a bearer Proof for [amount] via the mint (full BDHKE round-trip).
  Proof issue(Mint mint, int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig = mint.signIssue(amount, ctx.blinded)!;
    return Bdhke.unblind(ctx, sig, mint.publicKeyset.keyFor(amount)!);
  }

  test('issue then redeem, and a token cannot be redeemed twice', () {
    final mint = freshMint();
    final p = issue(mint, 8);
    expect(Bdhke.verifyOffline(p, mint.publicKeyset.keyFor(8)!), isTrue);
    expect(mint.redeem(p), isTrue);
    expect(mint.isSpent(p.secretHex), isTrue);
    expect(mint.redeem(p), isFalse); // already burned
  });

  test('swap makes exact change (split 8 -> 4+2+2) and burns the input', () {
    final mint = freshMint();
    final eight = issue(mint, 8);

    // Wallet blinds the change it wants.
    final c4 = Bdhke.blind(4, mint.keysetId);
    final c2a = Bdhke.blind(2, mint.keysetId);
    final c2b = Bdhke.blind(2, mint.keysetId);
    final sigs = mint.swap([eight], [
      BlindedOutput.of(c4),
      BlindedOutput.of(c2a),
      BlindedOutput.of(c2b),
    ])!;
    expect(sigs.length, 3);

    final out = [
      Bdhke.unblind(c4, sigs[0], mint.publicKeyset.keyFor(4)!),
      Bdhke.unblind(c2a, sigs[1], mint.publicKeyset.keyFor(2)!),
      Bdhke.unblind(c2b, sigs[2], mint.publicKeyset.keyFor(2)!),
    ];
    expect(out.fold<int>(0, (a, p) => a + p.amount), 8); // value conserved
    for (final p in out) {
      expect(Bdhke.verifyOffline(p, mint.publicKeyset.keyFor(p.amount)!), isTrue);
      expect(mint.redeem(p), isTrue); // freshly valid
    }
    // The melted input is now spent.
    expect(mint.redeem(eight), isFalse);
  });

  test('swap merges (4+4 -> 8)', () {
    final mint = freshMint();
    final a = issue(mint, 4);
    final b = issue(mint, 4);
    final c8 = Bdhke.blind(8, mint.keysetId);
    final sigs = mint.swap([a, b], [BlindedOutput.of(c8)])!;
    final merged = Bdhke.unblind(c8, sigs.single, mint.publicKeyset.keyFor(8)!);
    expect(merged.amount, 8);
    expect(mint.redeem(merged), isTrue);
  });

  test('swap rejects value mismatch and records nothing', () {
    final mint = freshMint();
    final eight = issue(mint, 8);
    final c4 = Bdhke.blind(4, mint.keysetId); // only 4 out for 8 in
    expect(mint.swap([eight], [BlindedOutput.of(c4)]), isNull);
    // Input was NOT burned by the failed swap.
    expect(mint.redeem(eight), isTrue);
  });

  test('swap rejects duplicate and already-spent inputs', () {
    final mint = freshMint();
    final four = issue(mint, 4);
    final c8 = Bdhke.blind(8, mint.keysetId);
    // Same input twice (would forge value).
    expect(mint.swap([four, four], [BlindedOutput.of(c8)]), isNull);
    // After a genuine redeem, the spent input can't be swapped.
    expect(mint.redeem(four), isTrue);
    final c4 = Bdhke.blind(4, mint.keysetId);
    expect(mint.swap([four], [BlindedOutput.of(c4)]), isNull);
  });
}
