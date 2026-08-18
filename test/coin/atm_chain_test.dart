import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/atm_chain.dart';
import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final mint = CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8);

  final atmA = NostrCrypto.generateKeyPair();
  final atmB = NostrCrypto.generateKeyPair();
  final alice = NostrCrypto.generateKeyPair();
  final bob = NostrCrypto.generateKeyPair();
  final carol = NostrCrypto.generateKeyPair();

  final privByPub = {
    atmA.publicKeyHex: atmA.privateKeyHex,
    atmB.publicKeyHex: atmB.privateKeyHex,
  };

  AtmChain freshChain() =>
      AtmChain(coinId, mint.public, [atmA.publicKeyHex, atmB.publicKeyHex]);

  String leaderPrivFor(AtmChain c, int height) =>
      privByPub[c.leaderFor(height)]!;

  Proof mintProof(int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig =
        Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!, ctx.blinded);
    return Bdhke.unblind(ctx, sig, mint.public.keyFor(amount)!);
  }

  test('grant credits an account', () {
    final c = freshChain();
    final grant =
        buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 100, 'g1');
    final b = c.produceBlock(leaderPrivFor(c, 0), [grant], time: 1000);
    expect(b, isNotNull);
    expect(c.state.balanceOf(alice.publicKeyHex), 100);
    expect(c.head!.height, 0);
  });

  test('transfer moves balance and rejects insufficient funds / replay', () {
    final c = freshChain();
    c.produceBlock(leaderPrivFor(c, 0),
        [buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 100, 'g1')],
        time: 1000);

    final t = buildTransferTx(
        coinId, alice.privateKeyHex, bob.publicKeyHex, 30, 'n1');
    final b1 = c.produceBlock(leaderPrivFor(c, 1), [t], time: 1001);
    expect(b1, isNotNull);
    expect(c.state.balanceOf(alice.publicKeyHex), 70);
    expect(c.state.balanceOf(bob.publicKeyHex), 30);

    // Overspend rejected.
    final tBad = buildTransferTx(
        coinId, bob.privateKeyHex, alice.publicKeyHex, 999, 'n2');
    expect(c.produceBlock(leaderPrivFor(c, 2), [tBad]), isNull);

    // Replayed nonce rejected.
    expect(c.produceBlock(leaderPrivFor(c, 2), [t]), isNull);
  });

  test('bearer redeem credits account and records the secret', () {
    final c = freshChain();
    final proof = mintProof(8);
    final redeem = buildRedeemTx(coinId, carol.privateKeyHex, proof);
    final b = c.produceBlock(leaderPrivFor(c, 0), [redeem], time: 1000);
    expect(b, isNotNull);
    expect(c.state.balanceOf(carol.publicKeyHex), 8);
    expect(c.state.spentSecrets.contains(proof.secretHex), isTrue);
  });

  test('the same bearer token cannot be redeemed twice (double-spend)', () {
    final c = freshChain();
    final proof = mintProof(8);
    c.produceBlock(leaderPrivFor(c, 0),
        [buildRedeemTx(coinId, carol.privateKeyHex, proof)],
        time: 1000);
    // A second redemption of the same secret (even to a different account) fails.
    final reuse = buildRedeemTx(coinId, bob.privateKeyHex, proof);
    expect(c.produceBlock(leaderPrivFor(c, 1), [reuse]), isNull);
  });

  test('a forged bearer token is rejected at redemption', () {
    final c = freshChain();
    final good = mintProof(8);
    final forged = Proof(good.amount, good.keysetId, good.secretHex,
        good.cHex, good.rHex, good.e, good.s + BigInt.one);
    final redeem = buildRedeemTx(coinId, carol.privateKeyHex, forged);
    expect(c.produceBlock(leaderPrivFor(c, 0), [redeem]), isNull);
  });

  test('a block from the wrong leader is not produced', () {
    final c = freshChain();
    final notLeader = c.leaderFor(0) == atmA.publicKeyHex
        ? atmB.privateKeyHex
        : atmA.privateKeyHex;
    final grant =
        buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 5, 'g1');
    expect(c.produceBlock(notLeader, [grant]), isNull);
  });

  test('blocks replicate to another node via appendBlock and match state', () {
    final c = freshChain();
    c.produceBlock(leaderPrivFor(c, 0),
        [buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 100, 'g1')],
        time: 1000);
    c.produceBlock(leaderPrivFor(c, 1), [
      buildTransferTx(coinId, alice.privateKeyHex, bob.publicKeyHex, 40, 'n1')
    ], time: 1001);

    // A second node validates and appends the same blocks from scratch.
    final mirror = freshChain();
    for (final b in c.blocks) {
      expect(mirror.appendBlock(b), isTrue);
    }
    expect(mirror.state.toJson().toString(), c.state.toJson().toString());
    expect(mirror.state.balanceOf(bob.publicKeyHex), 40);
  });

  test('appendBlock rejects a tampered block and a broken hash-link', () {
    final c = freshChain();
    final good = c.produceBlock(leaderPrivFor(c, 0),
        [buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 100, 'g1')],
        time: 1000)!;

    final mirror = freshChain();
    // Tamper: inflate the grant amount after signing -> hash/sig mismatch.
    final tampered = AtmBlock(
      coinId: good.coinId,
      height: good.height,
      prevHash: good.prevHash,
      txs: [
        {...good.txs.first, 'amount': 1000000}
      ],
      time: good.time,
      leader: good.leader,
      sig: good.sig,
    );
    expect(mirror.appendBlock(tampered), isFalse);
    // The genuine block still appends.
    expect(mirror.appendBlock(good), isTrue);
  });

  test('cosign adds a valid counter-signature from another ATM', () {
    final c = freshChain();
    final b = c.produceBlock(leaderPrivFor(c, 0),
        [buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 10, 'g1')],
        time: 1000)!;
    // The other ATM counter-signs; a fresh node accepts the cosigned block.
    final otherPriv = privByPub[c.leaderFor(0) == atmA.publicKeyHex
        ? atmB.publicKeyHex
        : atmA.publicKeyHex]!;
    final cosigned = AtmChain.cosign(b, otherPriv);
    expect(cosigned.cosigs.length, 1);
    final mirror = freshChain();
    expect(mirror.appendBlock(cosigned), isTrue);
  });
}
