import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/atm_chain.dart';
import 'package:reticulum/src/services/coin/authority_log.dart';
import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/fraud.dart';
import 'package:reticulum/src/services/coin/node_policy.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final mint = CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8);

  final atmA = NostrCrypto.generateKeyPair();
  final atmB = NostrCrypto.generateKeyPair();
  final alice = NostrCrypto.generateKeyPair(); // cheater (chain-sanctioned)
  final bob = NostrCrypto.generateKeyPair();
  final carol = NostrCrypto.generateKeyPair();

  final privByPub = {
    atmA.publicKeyHex: atmA.privateKeyHex,
    atmB.publicKeyHex: atmB.privateKeyHex,
  };
  String leaderPrivFor(AtmChain c, int h) => privByPub[c.leaderFor(h)]!;

  Proof mintProof(int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig =
        Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!, ctx.blinded);
    return Bdhke.unblind(ctx, sig, mint.public.keyFor(amount)!);
  }

  // Build a chain where Alice is freeze-sanctioned (offense at block time 2000).
  AccountState chainWithAliceFrozen() {
    final c = AtmChain(coinId, mint.public, [atmA.publicKeyHex, atmB.publicKeyHex]);
    final proof = mintProof(8);
    final toBob =
        SpendRecord.build(coinId, alice.privateKeyHex, proof.secretHex, bob.publicKeyHex);
    final toCarol =
        SpendRecord.build(coinId, alice.privateKeyHex, proof.secretHex, carol.publicKeyHex);
    c.produceBlock(leaderPrivFor(c, 0),
        [buildRedeemTx(coinId, bob.privateKeyHex, proof, spend: toBob)],
        time: 1000);
    c.produceBlock(
        leaderPrivFor(c, 1), [buildFraudTx(FraudProof(toBob, toCarol))],
        time: 2000);
    return c.state;
  }

  test('chain-derived freeze bars during the window only', () {
    final chain = chainWithAliceFrozen();
    final emptyAuth = CoinPolicy(coinId);
    final s = NodePolicy.status(alice.publicKeyHex, 2000,
        authority: emptyAuth, chain: chain);
    expect(s.barred, isTrue);
    expect(s.source, 'chain');
    expect(s.level, 'freeze');
    // After the freeze expires.
    expect(
        NodePolicy.isBarred(alice.publicKeyHex, 99999999,
            authority: emptyAuth, chain: chain),
        isFalse);
  });

  test('authority-log suspension bars on its own', () {
    final e = buildAuthority(admin.privateKeyHex, coinId, 0,
        opSanction(bob.publicKeyHex, SanctionLevel.suspend), createdAt: 500);
    final auth = reduceAuthority(coinId, [e]);
    final s = NodePolicy.status(bob.publicKeyHex, 9999,
        authority: auth, chain: null);
    expect(s.barred, isTrue);
    expect(s.source, 'authority');
    expect(s.level, 'suspend');
  });

  test('an admin lift at/after the offense overrides a chain sanction', () {
    final chain = chainWithAliceFrozen(); // offense at 2000
    // Admin lifts Alice at 3000 (>= offense) -> overrides.
    final lift = buildAuthority(admin.privateKeyHex, coinId, 0,
        opLift(alice.publicKeyHex), createdAt: 3000);
    final auth = reduceAuthority(coinId, [lift]);
    expect(
        NodePolicy.isBarred(alice.publicKeyHex, 2500,
            authority: auth, chain: chain),
        isFalse);
  });

  test('a lift predating the offense does NOT override', () {
    final chain = chainWithAliceFrozen(); // offense at 2000
    final earlyLift = buildAuthority(admin.privateKeyHex, coinId, 0,
        opLift(alice.publicKeyHex), createdAt: 1000); // before the offense
    final auth = reduceAuthority(coinId, [earlyLift]);
    expect(
        NodePolicy.isBarred(alice.publicKeyHex, 2500,
            authority: auth, chain: chain),
        isTrue);
  });

  test('debt is surfaced from the chain ledger', () {
    final chain = chainWithAliceFrozen();
    expect(NodePolicy.debtOf(alice.publicKeyHex, chain), 8);
  });
}
