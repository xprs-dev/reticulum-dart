import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/coin_ec.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  // A coin owned by some administrator; mint keys derived from a secret seed.
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final seed = NostrCrypto.generateKeyPair().privateKeyHex; // 32-byte hex seed
  final mint = CoinMintKeys.derive(coinId, seed, maxExp: 8);
  final keyset = mint.public;

  test('keyset id is stable and version-tagged', () {
    final again = CoinMintKeys.derive(coinId, seed, maxExp: 8);
    expect(again.keysetId, equals(mint.keysetId));
    expect(mint.keysetId.startsWith('00'), isTrue);
    expect(mint.keysetId.length, 16);
  });

  test('BDHKE round-trip: blind -> sign -> unblind -> verify offline & at mint',
      () {
    const amount = 8;
    final k = mint.privFor(amount)!;
    final K = keyset.keyFor(amount)!;

    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig = Bdhke.mintSign(amount, mint.keysetId, k, ctx.blinded);
    final proof = Bdhke.unblind(ctx, sig, K);

    // Third party verifies authenticity with no private key and no network.
    expect(Bdhke.verifyOffline(proof, K), isTrue);
    // Mint confirms on redemption.
    expect(Bdhke.mintVerify(proof, k), isTrue);
    expect(proof.amount, amount);
    expect(proof.keysetId, mint.keysetId);
  });

  test('tampered proof fails offline verification', () {
    const amount = 4;
    final k = mint.privFor(amount)!;
    final K = keyset.keyFor(amount)!;
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig = Bdhke.mintSign(amount, mint.keysetId, k, ctx.blinded);
    final good = Bdhke.unblind(ctx, sig, K);

    // Flip the secret -> C no longer matches; DLEQ re-blinding diverges.
    final forged = Proof(good.amount, good.keysetId,
        good.secretHex.replaceRange(0, 1, good.secretHex[0] == 'a' ? 'b' : 'a'),
        good.cHex, good.rHex, good.e, good.s);
    expect(Bdhke.verifyOffline(forged, K), isFalse);
    expect(Bdhke.mintVerify(forged, k), isFalse);
  });

  test('proof minted for one amount does not verify against another key', () {
    const amount = 2;
    final k = mint.privFor(amount)!;
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig = Bdhke.mintSign(amount, mint.keysetId, k, ctx.blinded);
    final proof = Bdhke.unblind(ctx, sig, keyset.keyFor(amount)!);

    // Verifying against a different denomination's key must fail.
    final otherK = keyset.keyFor(16)!;
    expect(Bdhke.verifyOffline(proof, otherK), isFalse);
  });

  test('bearer token encodes and decodes', () {
    const amount = 8;
    final k = mint.privFor(amount)!;
    final K = keyset.keyFor(amount)!;
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig = Bdhke.mintSign(amount, mint.keysetId, k, ctx.blinded);
    final proof = Bdhke.unblind(ctx, sig, K);

    final token = BearerToken(coinId, [proof]).encode();
    expect(token.startsWith('coin1'), isTrue);
    final decoded = BearerToken.decode(token)!;
    expect(decoded.coinId, coinId);
    expect(decoded.amount, amount);
    expect(Bdhke.verifyOffline(decoded.proofs.single, K), isTrue);
  });

  test('keyset public json round-trips', () {
    final json = keyset.toJson();
    final back = CoinKeyset.fromJson(json)!;
    expect(back.keysetId, keyset.keysetId);
    for (final a in [1, 2, 4, 8]) {
      expect(CoinEc.pointEq(back.keyFor(a)!, keyset.keyFor(a)!), isTrue);
    }
  });

  test('splitAmount yields powers of two summing to the amount', () {
    final parts = splitAmount(13, maxExp: 8); // 8 + 4 + 1
    expect(parts.fold<int>(0, (a, b) => a + b), 13);
    expect(parts, containsAll(<int>[8, 4, 1]));
  });
}
