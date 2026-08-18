import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/open.dart';

import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/wallet.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  // The app bundles SQLite via sqlite3_flutter_libs; the test VM only has the
  // versioned system lib, so point the loader at it.
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

  // Mint a bearer Proof for [amount] (full BDHKE round-trip).
  Proof mintProof(int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig = Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!,
        ctx.blinded);
    return Bdhke.unblind(ctx, sig, mint.public.keyFor(amount)!);
  }

  test('stores proofs and reports balance', () {
    final w = CoinWallet.open(':memory:');
    w.addAll(coinId, [mintProof(8), mintProof(4), mintProof(1)]);
    expect(w.balance(coinId), 13);
    expect(w.unspent(coinId).length, 3);
    w.close();
  });

  test('duplicate secret is not stored twice', () {
    final w = CoinWallet.open(':memory:');
    final p = mintProof(8);
    expect(w.add(coinId, p), isTrue);
    expect(w.add(coinId, p), isFalse); // same secret -> rejected
    expect(w.balance(coinId), 8);
    w.close();
  });

  test('selectForAmount covers the amount or returns empty', () {
    final w = CoinWallet.open(':memory:');
    w.addAll(coinId, [mintProof(8), mintProof(4), mintProof(2)]);
    final picked = w.selectForAmount(coinId, 10);
    expect(picked.fold<int>(0, (a, p) => a + p.amount), greaterThanOrEqualTo(10));
    expect(w.selectForAmount(coinId, 999), isEmpty); // insufficient
    w.close();
  });

  test('markSpent / isSpent and balance excludes spent', () {
    final w = CoinWallet.open(':memory:');
    final p = mintProof(8);
    w.add(coinId, p);
    expect(w.isSpent(p.secretHex), isFalse);
    w.markSpent(p.secretHex);
    expect(w.isSpent(p.secretHex), isTrue);
    expect(w.balance(coinId), 0); // spent no longer counts
    w.close();
  });

  test('stored proofs still verify offline after a round-trip through sqlite',
      () {
    final w = CoinWallet.open(':memory:');
    w.add(coinId, mintProof(8));
    final restored = w.unspent(coinId).single;
    expect(Bdhke.verifyOffline(restored, mint.public.keyFor(8)!), isTrue);
    w.close();
  });
}
