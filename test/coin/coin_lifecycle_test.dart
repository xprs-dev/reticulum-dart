// Full lifecycle simulation of a participation coin:
//   - an administrator creates the coin (signed authority log),
//   - three nodes volunteer to be ATMs; two are accepted, one is DENIED,
//   - the two accepted ATMs maintain the permissioned blockchain: every
//     transaction is written as a hash-linked block produced by the height's
//     leader and verified (appended + counter-signed) by the other ATM,
//   - faucet grants, an account transfer, a bearer-token redemption, and a
//     double-spend that is caught and sanctioned all flow through the chain,
//   - a fresh independent verifier replays the whole chain to the same state.
//
// This is the end-to-end exercise of authority_log + atm_chain + bearer_token +
// fraud, proving the pieces compose into a working coin.
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  NostrKeyPair kp() => NostrCrypto.generateKeyPair();

  test('full coin lifecycle: creation, ATM enrolment, ledger, sanctions', () {
    // ── Actors ────────────────────────────────────────────────────────────────
    final admin = kp(); // the coin administrator (owns the master key)
    final coinId = admin.publicKeyHex;
    final mint = CoinMintKeys.derive(
        coinId, kp().privateKeyHex, maxExp: 8); // the coin's mint keyset
    final keyset = mint.public;

    final atmA = kp(); // volunteer 1 — accepted
    final atmB = kp(); // volunteer 2 — accepted
    final atmC = kp(); // volunteer 3 — DENIED

    final alice = kp();
    final bob = kp();
    final carol = kp(); // will double-spend
    final dave = kp(); // defrauded victim

    // ── 1. Administrator creates the coin and sets monetary policy ─────────────
    final adm = CoinAdmin(admin.privateKeyHex);
    final authority = <NostrEvent>[
      adm.define(name: 'Mesh Credits', symbol: 'MSH', keyset: keyset, createdAt: 1000),
      adm.issue(1000, createdAt: 1001),
      adm.setFaucet({'reward': 5, 'cap': 100}, createdAt: 1002),
    ];

    // ── 2. Three nodes volunteer; the admin accepts A and B, DENIES C ──────────
    // (Denial = the admin never authorises C in the signed log.)
    authority.add(adm.addAtm(atmA.publicKeyHex, createdAt: 1003));
    authority.add(adm.addAtm(atmB.publicKeyHex, createdAt: 1004));

    final policy = reduceAuthority(coinId, authority);
    expect(policy.name, 'Mesh Credits');
    expect(policy.totalIssued, 1000);
    expect(policy.keyset?.keysetId, keyset.keysetId);
    final trusted = policy.activeAtms(2000).map((a) => a.pubkey).toSet();
    expect(trusted, {atmA.publicKeyHex, atmB.publicKeyHex});
    expect(trusted.contains(atmC.publicKeyHex), isFalse); // C is denied

    // A forged authority entry from C (pretending to enrol itself) is ignored.
    final forgedAuth = buildAuthority(atmC.privateKeyHex, coinId, 5,
        opAddAtm(atmC.publicKeyHex), createdAt: 1005);
    final policy2 = reduceAuthority(coinId, [...authority, forgedAuth]);
    expect(policy2.activeAtms(2000).map((a) => a.pubkey).toSet(),
        {atmA.publicKeyHex, atmB.publicKeyHex});

    // ── 3. The two accepted ATMs each maintain the blockchain ──────────────────
    final validators = [atmA.publicKeyHex, atmB.publicKeyHex];
    final chainA = AtmChain(coinId, keyset, validators);
    final chainB = AtmChain(coinId, keyset, validators);
    final priv = {
      atmA.publicKeyHex: atmA.privateKeyHex,
      atmB.publicKeyHex: atmB.privateKeyHex,
    };
    var clock = 2000;

    AtmChain chainOf(String pub) => pub == atmA.publicKeyHex ? chainA : chainB;
    String peerOf(String pub) =>
        pub == atmA.publicKeyHex ? atmB.publicKeyHex : atmA.publicKeyHex;

    // Commit one transaction batch as a block: the height's leader produces it,
    // the other ATM verifies + counter-signs + appends, and both ledgers must
    // then agree byte-for-byte on state.
    AtmBlock commit(List<Map<String, dynamic>> txs) {
      final height = chainA.blocks.length;
      final leaderPub = chainA.leaderFor(height);
      final block = chainOf(leaderPub)
          .produceBlock(priv[leaderPub]!, txs, time: clock++);
      expect(block, isNotNull,
          reason: 'leader ${leaderPub.substring(0, 6)} produces height $height');
      final cosigned = AtmChain.cosign(block!, priv[peerOf(leaderPub)]!);
      expect(chainOf(peerOf(leaderPub)).appendBlock(cosigned), isTrue,
          reason: 'peer ATM verifies and appends the block');
      // Both ATMs converge on the same state.
      expect(chainB.state.headHash, chainA.state.headHash);
      expect(chainB.state.balances.toString(), chainA.state.balances.toString());
      return block;
    }

    // ── 4. The DENIED node cannot participate ──────────────────────────────────
    // It cannot lead a block...
    final firstGrant =
        buildGrantTx(coinId, admin.privateKeyHex, alice.publicKeyHex, 100, 'g-a');
    expect(chainA.produceBlock(atmC.privateKeyHex, [firstGrant]), isNull);

    // ── 5. Faucet distributions, each written as its own block ─────────────────
    commit([firstGrant]); // grant alice 100
    commit([
      buildGrantTx(coinId, admin.privateKeyHex, bob.publicKeyHex, 50, 'g-b')
    ]); // grant bob 50
    expect(chainA.state.balanceOf(alice.publicKeyHex), 100);
    expect(chainA.state.balanceOf(bob.publicKeyHex), 50);

    // ...and a block forged by the denied node C is rejected on append.
    final h = chainA.blocks.length;
    final draft = AtmBlock(
      coinId: coinId,
      height: h,
      prevHash: chainA.blocks.last.hash,
      txs: const [],
      time: clock,
      leader: atmC.publicKeyHex,
      sig: '',
    );
    final forgedBlock = AtmBlock(
      coinId: coinId,
      height: h,
      prevHash: chainA.blocks.last.hash,
      txs: const [],
      time: clock,
      leader: atmC.publicKeyHex,
      sig: NostrCrypto.schnorrSign(draft.hash, atmC.privateKeyHex),
    );
    expect(chainA.appendBlock(forgedBlock), isFalse);

    // ── 6. An account transfer ────────────────────────────────────────────────
    commit([
      buildTransferTx(coinId, alice.privateKeyHex, bob.publicKeyHex, 30, 't-1')
    ]);
    expect(chainA.state.balanceOf(alice.publicKeyHex), 70);
    expect(chainA.state.balanceOf(bob.publicKeyHex), 80);

    // ── 7. A bearer token is issued and redeemed onto the chain ────────────────
    Proof mintBearer(int amount) {
      final ctx = Bdhke.blind(amount, mint.keysetId);
      final sig = Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!,
          ctx.blinded);
      return Bdhke.unblind(ctx, sig, keyset.keyFor(amount)!);
    }

    final carolToken = mintBearer(8); // issued to Carol
    commit([buildRedeemTx(coinId, carol.privateKeyHex, carolToken)]);
    expect(chainA.state.balanceOf(carol.publicKeyHex), 8);
    // The same token cannot be redeemed twice (spent-secret index).
    final hr = chainA.blocks.length;
    final leaderR = chainA.leaderFor(hr);
    expect(
        chainOf(leaderR).produceBlock(
            priv[leaderR]!, [buildRedeemTx(coinId, carol.privateKeyHex, carolToken)]),
        isNull);

    // ── 8. A double-spend is caught and sanctioned ─────────────────────────────
    final cheatToken = mintBearer(4); // Carol holds it and double-spends offline
    final toBob = SpendRecord.build(
        coinId, carol.privateKeyHex, cheatToken.secretHex, bob.publicKeyHex);
    final toDave = SpendRecord.build(
        coinId, carol.privateKeyHex, cheatToken.secretHex, dave.publicKeyHex);

    // Bob redeems first (collects the value), with provenance.
    commit([buildRedeemTx(coinId, bob.privateKeyHex, cheatToken, spend: toBob)]);
    final bobBefore = chainA.state.balanceOf(bob.publicKeyHex);

    // Dave's redemption of the same token is rejected by the ledger.
    final hd = chainA.blocks.length;
    final leaderD = chainA.leaderFor(hd);
    expect(
        chainOf(leaderD).produceBlock(priv[leaderD]!,
            [buildRedeemTx(coinId, dave.privateKeyHex, cheatToken, spend: toDave)]),
        isNull);

    // An ATM submits the self-proving fraud evidence; it is committed.
    commit([buildFraudTx(FraudProof(toBob, toDave))]);
    final s = chainA.state;
    expect(s.isSanctioned(carol.publicKeyHex, clock), isTrue); // Carol frozen
    expect(s.balanceOf(dave.publicKeyHex), 4); // victim reimbursed
    expect(s.balanceOf(carol.publicKeyHex), 4); // 8 collected − 4 clawed back
    expect(s.balanceOf(bob.publicKeyHex), bobBefore); // honest collector kept it

    // ── 9. The chain is hash-linked, and any node can verify the whole thing ───
    for (var i = 1; i < chainA.blocks.length; i++) {
      expect(chainA.blocks[i].prevHash, chainA.blocks[i - 1].hash);
    }
    expect(chainA.state.height, chainA.blocks.length - 1);

    // A brand-new independent verifier replays every block from scratch and
    // reaches the identical state — "written and verified by each ATM".
    final verifier = AtmChain(coinId, keyset, validators);
    for (final b in chainA.blocks) {
      expect(verifier.appendBlock(b), isTrue);
    }
    expect(verifier.state.toJson().toString(), chainA.state.toJson().toString());
    expect(verifier.state.toJson().toString(), chainB.state.toJson().toString());
  });
}
