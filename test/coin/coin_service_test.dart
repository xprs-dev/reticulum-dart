import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/open.dart';

import 'package:reticulum/src/services/coin/atm_chain.dart';
import 'package:reticulum/src/services/coin/authority_log.dart';
import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/coin_service.dart';
import 'package:reticulum/src/services/coin/postage.dart';
import 'package:reticulum/src/services/coin/wallet.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  setUpAll(() {
    if (Platform.isLinux) {
      open.overrideFor(
          OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));
    }
  });

  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final mint = CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8);
  final keyset = mint.public;

  final atmA = NostrCrypto.generateKeyPair();
  final atmB = NostrCrypto.generateKeyPair();
  final alice = NostrCrypto.generateKeyPair();
  final bob = NostrCrypto.generateKeyPair();
  final relay = NostrCrypto.generateKeyPair();

  final privByPub = {
    atmA.publicKeyHex: atmA.privateKeyHex,
    atmB.publicKeyHex: atmB.privateKeyHex,
  };
  AtmChain freshChain() =>
      AtmChain(coinId, keyset, [atmA.publicKeyHex, atmB.publicKeyHex]);
  String leaderPrivFor(AtmChain c, int h) => privByPub[c.leaderFor(h)]!;

  Proof mintProof(int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig =
        Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!, ctx.blinded);
    return Bdhke.unblind(ctx, sig, keyset.keyFor(amount)!);
  }

  CoinService service(NostrKeyPair who) => CoinService(
        coinId: coinId,
        myPriv: who.privateKeyHex,
        keyset: keyset,
        wallet: CoinWallet.open(':memory:'),
      );

  test('CoinAdmin emits a valid, replay-resistant authority chain', () {
    final adm = CoinAdmin(admin.privateKeyHex);
    final events = [
      adm.define(name: 'Mesh', symbol: 'MSH', keyset: keyset, createdAt: 1000),
      adm.issue(1000, createdAt: 1001),
      adm.addAtm(atmA.publicKeyHex, createdAt: 1002),
      adm.grant(alice.publicKeyHex, 50, createdAt: 1003),
    ];
    final policy = reduceAuthority(coinId, events);
    expect(policy.name, 'Mesh');
    expect(policy.totalIssued, 1000);
    expect(policy.totalGranted, 50);
    expect(policy.keyset?.keysetId, keyset.keysetId);
    expect(policy.lastSeq, 3);

    // A second admin resumes from the reduced policy and continues the sequence.
    final adm2 = CoinAdmin(admin.privateKeyHex, resumeFrom: policy);
    expect(adm2.nextSeq, 4);
    final more = adm2.issue(5, createdAt: 1004);
    final policy2 = reduceAuthority(coinId, [...events, more]);
    expect(policy2.totalIssued, 1005);
    expect(policy2.lastSeq, 4);
  });

  test('store proofs and report wallet balance; reject inauthentic proofs', () {
    final s = service(alice);
    expect(s.storeProofs([mintProof(8), mintProof(4)]), 12);
    expect(s.walletBalance(), 12);
    // A forged proof is not stored.
    final good = mintProof(2);
    final forged =
        Proof(good.amount, good.keysetId, good.secretHex, good.cHex, good.rHex,
            good.e, good.s + BigInt.one);
    expect(s.storeProofs([forged]), 0);
    expect(s.walletBalance(), 12);
  });

  test('offline hand-off: send reserves, receive verifies and credits', () {
    final aliceSvc = service(alice);
    final bobSvc = service(bob);
    aliceSvc.storeProofs([mintProof(8), mintProof(4)]);

    final handoff = aliceSvc.sendOffline(bob.publicKeyHex, 8)!;
    expect(handoff.amount, greaterThanOrEqualTo(8));
    // Reserved locally (spent), so Alice can't reuse them.
    expect(aliceSvc.walletBalance(), 12 - handoff.amount);

    // Survives serialization (e.g. over BLE/APRS).
    final wire = OfflineHandoff.fromJson(handoff.toJson())!;
    final received = bobSvc.receiveOffline(wire);
    expect(received, handoff.amount);
    expect(bobSvc.walletBalance(), handoff.amount);

    // A handoff addressed to Alice is not accepted by Bob's peer.
    final other = service(relay);
    expect(other.receiveOffline(wire), 0);
  });

  test('postage is built from holdings and settles on the chain', () {
    final s = service(alice);
    s.storeProofs([mintProof(1), mintProof(2)]);
    final postage = s.buildPostage(relay.publicKeyHex, 1)!;
    expect(postage, isNotEmpty);
    for (final p in postage) {
      expect(Postage.verify(coinId, p, keyset, relay.publicKeyHex), isTrue);
    }
    // Relay settles the postage.
    final c = freshChain();
    final txs = [
      for (final p in postage)
        buildRedeemTx(coinId, relay.privateKeyHex, p.proof, spend: p.spend)
    ];
    c.produceBlock(leaderPrivFor(c, 0), txs, time: 1000);
    expect(c.state.balanceOf(relay.publicKeyHex), greaterThanOrEqualTo(1));
  });

  test('redeem bearer holdings into an on-chain account, then transfer', () {
    final aliceSvc = service(alice);
    aliceSvc.storeProofs([mintProof(8), mintProof(2)]);

    final c = freshChain();
    final redeemTxs = aliceSvc.redeemToAccount();
    c.produceBlock(leaderPrivFor(c, 0), redeemTxs, time: 1000);
    expect(aliceSvc.accountBalance(c.state), 10);
    expect(aliceSvc.walletBalance(), 0); // bearer holdings consumed

    // Online transfer 6 to Bob.
    final t = aliceSvc.buildTransfer(bob.publicKeyHex, 6, 'n1');
    c.produceBlock(leaderPrivFor(c, 1), [t], time: 1001);
    expect(aliceSvc.accountBalance(c.state), 4);
    expect(c.state.balanceOf(bob.publicKeyHex), 6);
  });
}
