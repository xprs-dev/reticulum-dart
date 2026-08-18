import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/atm_chain.dart';
import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/faucet.dart';
import 'package:reticulum/src/services/coin/postage.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final mint = CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8);

  final atmA = NostrCrypto.generateKeyPair();
  final atmB = NostrCrypto.generateKeyPair();
  final sender = NostrCrypto.generateKeyPair();
  final relay = NostrCrypto.generateKeyPair();
  final recipient = NostrCrypto.generateKeyPair();

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

  group('free tier', () {
    test('allows up to the allowance, then requires postage', () {
      final meter = FreeTierMeter(const FreeTierPolicy(windowSeconds: 100, maxFree: 3));
      const t = 1000;
      expect(meter.allow(sender.publicKeyHex, t), isTrue);
      expect(meter.allow(sender.publicKeyHex, t), isTrue);
      expect(meter.allow(sender.publicKeyHex, t), isTrue);
      expect(meter.remaining(sender.publicKeyHex, t), 0);
      expect(meter.allow(sender.publicKeyHex, t), isFalse); // over allowance
    });

    test('allowance refills after the window slides', () {
      final meter = FreeTierMeter(const FreeTierPolicy(windowSeconds: 100, maxFree: 1));
      expect(meter.allow(sender.publicKeyHex, 1000), isTrue);
      expect(meter.allow(sender.publicKeyHex, 1050), isFalse);
      expect(meter.allow(sender.publicKeyHex, 1101), isTrue); // old hit pruned
    });
  });

  group('postage', () {
    test('verifies offline for the named relay and settles single-use', () {
      final proof = mintProof(1);
      final postage = Postage.build(coinId, sender.privateKeyHex, proof,
          relay.publicKeyHex);
      expect(Postage.verify(coinId, postage, mint.public, relay.publicKeyHex),
          isTrue);
      // Wrong relay rejects.
      expect(
          Postage.verify(coinId, postage, mint.public, recipient.publicKeyHex),
          isFalse);

      // The relay settles the postage on-chain and is credited once.
      final c = freshChain();
      final tx = buildRedeemTx(coinId, relay.privateKeyHex, postage.proof,
          spend: postage.spend);
      expect(c.produceBlock(leaderPrivFor(c, 0), [tx], time: 1000), isNotNull);
      expect(c.state.balanceOf(relay.publicKeyHex), 1);
      // Re-settling the same postage is rejected (double-spend).
      expect(c.produceBlock(leaderPrivFor(c, 1), [tx]), isNull);
    });

    test('postage json round-trips', () {
      final postage = Postage.build(coinId, sender.privateKeyHex, mintProof(2),
          relay.publicKeyHex);
      final back = Postage.fromJson(postage.toJson())!;
      expect(back.amount, 2);
      expect(back.relay, relay.publicKeyHex);
    });
  });

  group('faucet', () {
    test('rewards verified delivery receipts, capped per window', () {
      final faucet = Faucet(coinId, admin.privateKeyHex,
          const FaucetRules(workPerReceipt: 1, workCapPerWindow: 2));
      // Five receipts from distinct recipients to the same relay.
      final receipts = [
        for (var i = 0; i < 5; i++)
          DeliveryReceipt.build(coinId,
              NostrCrypto.generateKeyPair().privateKeyHex, relay.publicKeyHex,
              'msg$i')
      ];
      final txs = faucet.issueForReceipts(receipts, 1000);
      expect(txs.length, 1); // aggregated for the one relay
      // Capped at 2 despite 5 receipts.
      final c = freshChain();
      c.produceBlock(leaderPrivFor(c, 0), txs, time: 1000);
      expect(c.state.balanceOf(relay.publicKeyHex), 2);
    });

    test('drops self-dealing and duplicate receipts', () {
      final faucet = Faucet(coinId, admin.privateKeyHex, const FaucetRules());
      // recipient == relay (self-dealing) is ignored.
      final self = DeliveryReceipt.build(
          coinId, relay.privateKeyHex, relay.publicKeyHex, 'm1');
      expect(faucet.issueForReceipts([self], 1000), isEmpty);

      final r = DeliveryReceipt.build(
          coinId, recipient.privateKeyHex, relay.publicKeyHex, 'm2');
      expect(faucet.issueForReceipts([r], 1000).length, 1);
      // The same receipt again earns nothing.
      expect(faucet.issueForReceipts([r], 1000), isEmpty);
    });

    test('bootstrap grant is sized by trust and one-time', () {
      final faucet = Faucet(coinId, admin.privateKeyHex,
          const FaucetRules(bootstrapMax: 10));
      final newcomer = NostrCrypto.generateKeyPair().publicKeyHex;
      expect(faucet.bootstrap(newcomer, 0.0), isNull); // no trust -> nothing
      final tx = faucet.bootstrap(newcomer, 1.0)!; // full trust -> max
      final c = freshChain();
      c.produceBlock(leaderPrivFor(c, 0), [tx], time: 1000);
      expect(c.state.balanceOf(newcomer), 10);
      expect(faucet.bootstrap(newcomer, 1.0), isNull); // only once
    });
  });
}
