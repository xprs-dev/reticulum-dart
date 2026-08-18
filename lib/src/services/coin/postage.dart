/*
 * postage — anti-spam at message spend time, with a free emergency tier.
 *
 * Casual and emergency messaging is FREE: every identity gets a low-bandwidth
 * allowance (FreeTierMeter) so a distress message is never gated behind coins.
 * Only sustained volume above that allowance — or advanced features — needs
 * consumable Postage: a small bearer token the sender hands to the relay (a
 * bearer Proof + a SpendRecord naming the relay), verifiable offline and
 * single-use once the relay settles it on the ATM chain. Spammers exhaust the
 * free allowance instantly and must then pay, and paying drains coins faster than
 * the faucet grants them, so spam is self-limiting.
 *
 * This module is self-contained and does NOT modify the shared SpamPolicy; see
 * "Wiring" below for how lib/services/social/spam.dart would call it.
 *
 * Pure/headless: bearer_token + fraud(SpendRecord) + coin_keyset.
 *
 * Wiring (when integrating, do it in spam.dart, not here):
 *   final meter = FreeTierMeter(policy);
 *   if (meter.allow(senderPub, now) && !needsAdvancedFeature) accept;     // free
 *   else require a valid Postage: Postage.verify(coinId, postage, keyset) // paid
 *        then hand it to an ATM as buildRedeemTx(coinId, relayPriv, proof, spend).
 */
import 'bearer_token.dart';
import 'coin_keyset.dart';
import 'fraud.dart';

/// Per-key free messaging allowance: [maxFree] messages per [windowSeconds].
class FreeTierPolicy {
  final int windowSeconds;
  final int maxFree;
  const FreeTierPolicy({this.windowSeconds = 3600, this.maxFree = 30});

  static FreeTierPolicy fromMap(Map<String, dynamic> m) => FreeTierPolicy(
        windowSeconds:
            m['windowSeconds'] is int ? m['windowSeconds'] as int : 3600,
        maxFree: m['maxFree'] is int ? m['maxFree'] as int : 30,
      );

  Map<String, dynamic> toMap() =>
      {'windowSeconds': windowSeconds, 'maxFree': maxFree};
}

/// In-memory per-key rate limiter for the free tier. A real relay can persist
/// this; the logic is the sliding-window count.
class FreeTierMeter {
  final FreeTierPolicy policy;
  final Map<String, List<int>> _hits = {}; // pubkey -> message times (secs)

  FreeTierMeter(this.policy);

  void _prune(String pub, int now) {
    final cutoff = now - policy.windowSeconds;
    final list = _hits[pub];
    if (list == null) return;
    list.removeWhere((t) => t < cutoff);
    if (list.isEmpty) _hits.remove(pub);
  }

  /// Free messages still available to [pub] in the current window.
  int remaining(String pub, int now) {
    _prune(pub, now);
    final used = _hits[pub]?.length ?? 0;
    final left = policy.maxFree - used;
    return left < 0 ? 0 : left;
  }

  /// Try to send one free message. Returns true and records it if the sender is
  /// still within the free allowance; false if they must attach postage.
  bool allow(String pub, int now) {
    if (remaining(pub, now) <= 0) return false;
    (_hits[pub] ??= []).add(now);
    return true;
  }
}

/// A consumable stamp: a bearer [proof] handed to a relay via a signed [spend]
/// record. The relay verifies it offline and later settles it on the ATM chain.
class Postage {
  final Proof proof;
  final SpendRecord spend; // secret -> relay

  const Postage(this.proof, this.spend);

  int get amount => proof.amount;
  String get relay => spend.to;

  /// Build postage worth [proof] paid by [senderPriv]'s owner to [relayPub].
  factory Postage.build(String coinId, String senderPriv, Proof proof,
          String relayPub) =>
      Postage(proof,
          SpendRecord.build(coinId, senderPriv, proof.secretHex, relayPub));

  Map<String, dynamic> toJson() =>
      {'proof': proof.toJson(), 'spend': spend.toJson()};

  static Postage? fromJson(Object? o) {
    if (o is! Map) return null;
    final proof = Proof.fromJson(o['proof']);
    final spend = SpendRecord.fromJson(o['spend']);
    if (proof == null || spend == null) return null;
    return Postage(proof, spend);
  }

  /// Verify postage offline for [relayPub]: the token is authentic (DLEQ against
  /// the published [keyset]), the handoff record is well-formed and signed, and
  /// it actually names this relay. Does NOT check double-spend — that is the
  /// chain's job when the relay settles it.
  static bool verify(
      String coinId, Postage postage, CoinKeyset keyset, String relayPub) {
    final p = postage.proof;
    if (postage.spend.coinId != coinId) return false;
    if (postage.spend.secret != p.secretHex) return false;
    if (postage.spend.to != relayPub) return false;
    if (!postage.spend.verify()) return false;
    final k = keyset.keyFor(p.amount);
    if (k == null) return false;
    return Bdhke.verifyOffline(p, k);
  }
}
