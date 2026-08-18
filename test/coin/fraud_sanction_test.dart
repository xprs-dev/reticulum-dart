import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/atm_chain.dart';
import 'package:reticulum/src/services/coin/authority_log.dart' show SanctionLevel;
import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/fraud.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final mint = CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8);

  final atmA = NostrCrypto.generateKeyPair();
  final atmB = NostrCrypto.generateKeyPair();
  final alice = NostrCrypto.generateKeyPair(); // the cheater (holds the token)
  final bob = NostrCrypto.generateKeyPair(); // first receiver (collects)
  final carol = NostrCrypto.generateKeyPair(); // defrauded victim
  final dave = NostrCrypto.generateKeyPair();

  final privByPub = {
    atmA.publicKeyHex: atmA.privateKeyHex,
    atmB.publicKeyHex: atmB.privateKeyHex,
  };

  AtmChain freshChain() =>
      AtmChain(coinId, mint.public, [atmA.publicKeyHex, atmB.publicKeyHex]);
  String leaderPrivFor(AtmChain c, int h) => privByPub[c.leaderFor(h)]!;

  Proof mintProof(int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig =
        Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!, ctx.blinded);
    return Bdhke.unblind(ctx, sig, mint.public.keyFor(amount)!);
  }

  test('spend record and fraud proof verify only when genuinely conflicting',
      () {
    final proof = mintProof(8);
    final toBob = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, bob.publicKeyHex);
    final toCarol = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, carol.publicKeyHex);
    expect(toBob.verify(), isTrue);
    expect(FraudProof(toBob, toCarol).verify(), isTrue); // same token, two takers
    // Same recipient twice is not fraud.
    expect(FraudProof(toBob, toBob).verify(), isFalse);
  });

  // Offline double-spend: Alice hands the same token to Bob and Carol.
  test('double-spend freezes the cheater, claws back, and reimburses the victim',
      () {
    final c = freshChain();
    final proof = mintProof(8);
    final toBob = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, bob.publicKeyHex);
    final toCarol = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, carol.publicKeyHex);

    // Bob redeems first (collects the value).
    c.produceBlock(leaderPrivFor(c, 0),
        [buildRedeemTx(coinId, bob.privateKeyHex, proof, spend: toBob)],
        time: 1000);
    expect(c.state.balanceOf(bob.publicKeyHex), 8);

    // Carol's redemption of the same token is rejected (already spent).
    expect(
        c.produceBlock(leaderPrivFor(c, 1),
            [buildRedeemTx(coinId, carol.privateKeyHex, proof, spend: toCarol)]),
        isNull);

    // An ATM submits the self-proving fraud evidence.
    final fraud = buildFraudTx(FraudProof(toBob, toCarol));
    final b = c.produceBlock(leaderPrivFor(c, 1), [fraud], time: 2000);
    expect(b, isNotNull);

    final s = c.state;
    expect(s.isSanctioned(alice.publicKeyHex, 2000), isTrue);
    expect(s.sanctions[alice.publicKeyHex]!.level, SanctionLevel.freeze);
    expect(s.balanceOf(carol.publicKeyHex), 8); // victim reimbursed
    expect(s.debtOf(alice.publicKeyHex), 8); // cheater owes the clawback
    expect(s.balanceOf(bob.publicKeyHex), 8); // honest collector unaffected
    // Freeze expires; it is not indefinite.
    expect(s.isSanctioned(alice.publicKeyHex, 99999999), isFalse);
  });

  test('a repeat double-spend escalates to suspension', () {
    final c = freshChain();

    // First offense.
    final p1 = mintProof(8);
    final p1Bob = SpendRecord.build(
        coinId, alice.privateKeyHex, p1.secretHex, bob.publicKeyHex);
    final p1Carol = SpendRecord.build(
        coinId, alice.privateKeyHex, p1.secretHex, carol.publicKeyHex);
    c.produceBlock(leaderPrivFor(c, 0),
        [buildRedeemTx(coinId, bob.privateKeyHex, p1, spend: p1Bob)],
        time: 1000);
    c.produceBlock(
        leaderPrivFor(c, 1), [buildFraudTx(FraudProof(p1Bob, p1Carol))],
        time: 2000);
    expect(c.state.sanctions[alice.publicKeyHex]!.level, SanctionLevel.freeze);

    // Second offense with a different token.
    final p2 = mintProof(4);
    final p2Bob = SpendRecord.build(
        coinId, alice.privateKeyHex, p2.secretHex, bob.publicKeyHex);
    final p2Dave = SpendRecord.build(
        coinId, alice.privateKeyHex, p2.secretHex, dave.publicKeyHex);
    c.produceBlock(leaderPrivFor(c, 2),
        [buildRedeemTx(coinId, bob.privateKeyHex, p2, spend: p2Bob)],
        time: 3000);
    c.produceBlock(
        leaderPrivFor(c, 3), [buildFraudTx(FraudProof(p2Bob, p2Dave))],
        time: 4000);

    final s = c.state;
    expect(s.sanctions[alice.publicKeyHex]!.level, SanctionLevel.suspend);
    expect(s.isSanctioned(alice.publicKeyHex, 99999999), isTrue); // indefinite
  });

  test('fraud over a token that never settled on-chain is rejected', () {
    final c = freshChain();
    final proof = mintProof(8);
    final toBob = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, bob.publicKeyHex);
    final toCarol = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, carol.publicKeyHex);
    // No redeem happened, so the chain has no settlement to attribute.
    expect(
        c.produceBlock(
            leaderPrivFor(c, 0), [buildFraudTx(FraudProof(toBob, toCarol))]),
        isNull);
  });

  test('the same fraud cannot be adjudicated twice (idempotent)', () {
    final c = freshChain();
    final proof = mintProof(8);
    final toBob = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, bob.publicKeyHex);
    final toCarol = SpendRecord.build(
        coinId, alice.privateKeyHex, proof.secretHex, carol.publicKeyHex);
    c.produceBlock(leaderPrivFor(c, 0),
        [buildRedeemTx(coinId, bob.privateKeyHex, proof, spend: toBob)],
        time: 1000);
    c.produceBlock(
        leaderPrivFor(c, 1), [buildFraudTx(FraudProof(toBob, toCarol))],
        time: 2000);
    // Replaying the same fraud evidence must not double-reimburse.
    expect(
        c.produceBlock(
            leaderPrivFor(c, 2), [buildFraudTx(FraudProof(toBob, toCarol))]),
        isNull);
    expect(c.state.balanceOf(carol.publicKeyHex), 8); // not 16
  });
}
