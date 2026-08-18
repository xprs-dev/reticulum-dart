import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/bearer_token.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/services/coin/postage.dart';
import 'package:reticulum/src/services/coin/postage_gate.dart';
import 'package:reticulum/src/services/social/spam.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';
import 'package:reticulum/src/util/nostr_event.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final coinId = admin.publicKeyHex;
  final mint = CoinMintKeys.derive(
      coinId, NostrCrypto.generateKeyPair().privateKeyHex,
      maxExp: 8);
  final keyset = mint.public;

  final relay = NostrCrypto.generateKeyPair();
  final sender = NostrCrypto.generateKeyPair();

  Proof mintProof(int amount) {
    final ctx = Bdhke.blind(amount, mint.keysetId);
    final sig =
        Bdhke.mintSign(amount, mint.keysetId, mint.privFor(amount)!, ctx.blinded);
    return Bdhke.unblind(ctx, sig, keyset.keyFor(amount)!);
  }

  NostrEvent event(String priv, {List<List<String>> tags = const [], int t = 1}) {
    final e = NostrEvent(
      pubkey: NostrCrypto.derivePublicKey(priv),
      createdAt: t,
      kind: 1,
      tags: tags,
      content: 'hello',
    );
    e.sign(priv);
    return e;
  }

  List<List<String>> postageTags(String relayPub, int amount) =>
      [postageTag(Postage.build(coinId, sender.privateKeyHex, mintProof(amount), relayPub))];

  SpamPolicy policy() => SpamPolicy(
        maxEventsPerWindow: 1,
        postageValidator: makePostageValidator(
            coinId: coinId, keyset: keyset, relayPub: relay.publicKeyHex),
      );

  test('reads back postage attached to an event', () {
    final e = event(sender.privateKeyHex, tags: postageTags(relay.publicKeyHex, 2));
    final p = readPostage(e);
    expect(p, isNotNull);
    expect(p!.amount, 2);
    expect(p.relay, relay.publicKeyHex);
  });

  test('free tier accepts up to the limit, then postage is required', () {
    final p = policy();
    // First (free) message accepted.
    expect(p.check(event(sender.privateKeyHex), nowMs: 1000).accepted, isTrue);
    // Second within the window: over the free allowance, no postage -> rejected.
    final r = p.check(event(sender.privateKeyHex), nowMs: 1001);
    expect(r.accepted, isFalse);
    expect(r.reason, 'rate limited');
    // Same situation but carrying valid postage -> accepted (paid path).
    final paid = event(sender.privateKeyHex, tags: postageTags(relay.publicKeyHex, 1));
    expect(p.check(paid, nowMs: 1002).accepted, isTrue);
  });

  test('advanced features require postage regardless of the free allowance', () {
    final p = policy();
    // requirePostage with no postage -> rejected even as the first message.
    final r = p.check(event(sender.privateKeyHex), nowMs: 1000, requirePostage: true);
    expect(r.accepted, isFalse);
    expect(r.reason, 'postage required');
    // With valid postage -> accepted.
    final paid = event(sender.privateKeyHex, tags: postageTags(relay.publicKeyHex, 1));
    expect(p.check(paid, nowMs: 1001, requirePostage: true).accepted, isTrue);
  });

  test('postage payable to a different relay does not count', () {
    final p = policy();
    final other = NostrCrypto.generateKeyPair();
    p.check(event(sender.privateKeyHex), nowMs: 1000); // use up free allowance
    final wrong = event(sender.privateKeyHex, tags: postageTags(other.publicKeyHex, 1));
    expect(p.check(wrong, nowMs: 1001).accepted, isFalse); // not this relay's postage
  });

  test('backward compatible: no validator behaves exactly as before', () {
    final p = SpamPolicy(maxEventsPerWindow: 1);
    expect(p.check(event(sender.privateKeyHex), nowMs: 1000).accepted, isTrue);
    final r = p.check(event(sender.privateKeyHex), nowMs: 1001);
    expect(r.accepted, isFalse);
    expect(r.reason, 'rate limited');
  });
}
