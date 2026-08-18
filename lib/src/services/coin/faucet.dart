/*
 * faucet — automatic participation rewards (net-new issuance) per the coin's
 * administrator-defined rules (CoinPolicy.faucetRules).
 *
 * Earning has three sources (see docs/aurora-coin.md §8). The PRIMARY one —
 * recycled postage — needs no faucet code: when a relay settles postage it is
 * already credited on the ATM chain (a redeem). This module handles the two
 * NET-NEW sources, both emitted as administrator-signed grant txs so they settle
 * like any coinbase:
 *
 *   1. Capped useful-work issuance — a relay is rewarded for delivering a message
 *      ONLY on a DeliveryReceipt signed by the RECIPIENT (not the relayer), and
 *      only up to a per-window cap, which bounds collusion/Sybil farming.
 *   2. Bootstrap grant — a tiny one-time grant sized by the newcomer's anchored
 *      trust score (computed elsewhere from the follow graph), so spammer cliques
 *      with no inbound anchor edge get ~nothing.
 *
 * Pure/headless: nostr_crypto + atm_chain(buildGrantTx).
 */
import '../../util/nostr_crypto.dart';
import 'atm_chain.dart';

/// Administrator-tunable reward parameters.
class FaucetRules {
  final int workPerReceipt; // reward per verified delivery receipt
  final int workCapPerWindow; // max useful-work issuance per relay per window
  final int windowSeconds;
  final int bootstrapMax; // max bootstrap grant at full trust

  const FaucetRules({
    this.workPerReceipt = 1,
    this.workCapPerWindow = 100,
    this.windowSeconds = 24 * 3600,
    this.bootstrapMax = 10,
  });

  static FaucetRules fromMap(Map<String, dynamic> m) => FaucetRules(
        workPerReceipt:
            m['workPerReceipt'] is int ? m['workPerReceipt'] as int : 1,
        workCapPerWindow:
            m['workCapPerWindow'] is int ? m['workCapPerWindow'] as int : 100,
        windowSeconds:
            m['windowSeconds'] is int ? m['windowSeconds'] as int : 24 * 3600,
        bootstrapMax: m['bootstrapMax'] is int ? m['bootstrapMax'] as int : 10,
      );

  Map<String, dynamic> toMap() => {
        'workPerReceipt': workPerReceipt,
        'workCapPerWindow': workCapPerWindow,
        'windowSeconds': windowSeconds,
        'bootstrapMax': bootstrapMax,
      };
}

/// Proof a message was delivered: signed by the RECIPIENT, crediting the relay.
class DeliveryReceipt {
  final String coinId;
  final String relay; // who carried the message (to be rewarded)
  final String messageId;
  final String recipient; // signer
  final String sig;

  const DeliveryReceipt(
      this.coinId, this.relay, this.messageId, this.recipient, this.sig);

  static String signingHash(
          String coinId, String relay, String messageId, String recipient) =>
      NostrCrypto.sha256Hash('receipt|$coinId|$relay|$messageId|$recipient');

  factory DeliveryReceipt.build(
      String coinId, String recipientPriv, String relay, String messageId) {
    final recipient = NostrCrypto.derivePublicKey(recipientPriv);
    final sig = NostrCrypto.schnorrSign(
        signingHash(coinId, relay, messageId, recipient), recipientPriv);
    return DeliveryReceipt(coinId, relay, messageId, recipient, sig);
  }

  bool verify() => NostrCrypto.schnorrVerify(
      signingHash(coinId, relay, messageId, recipient), sig, recipient);

  /// A receipt is double-counted if the same (relay, message, recipient) repeats.
  String get key => '$relay|$messageId|$recipient';

  Map<String, dynamic> toJson() => {
        'coinId': coinId,
        'relay': relay,
        'messageId': messageId,
        'recipient': recipient,
        'sig': sig,
      };

  static DeliveryReceipt? fromJson(Object? o) {
    if (o is! Map) return null;
    final c = o['coinId'], r = o['relay'], m = o['messageId'];
    final rec = o['recipient'], s = o['sig'];
    if (c is! String ||
        r is! String ||
        m is! String ||
        rec is! String ||
        s is! String) {
      return null;
    }
    return DeliveryReceipt(c, r, m, rec, s);
  }
}

/// Stateful faucet at the administrator/mint: turns participation into capped,
/// administrator-signed grant txs. Tracks per-relay issuance windows and the
/// receipts already rewarded.
class Faucet {
  final String coinId;
  final String adminPriv;
  final FaucetRules rules;

  final Map<String, _Window> _work = {}; // relay -> window accounting
  final Set<String> _seenReceipts = {}; // receipt keys already rewarded
  final Set<String> _bootstrapped = {}; // newcomers already bootstrapped

  Faucet(this.coinId, this.adminPriv, this.rules);

  /// Reward verified delivery [receipts], honoring the per-relay window cap.
  /// Returns the grant txs to include on the ATM chain (one per rewarded relay,
  /// aggregated). Invalid, duplicate, or over-cap receipts are dropped/clamped.
  List<Map<String, dynamic>> issueForReceipts(
      List<DeliveryReceipt> receipts, int now) {
    final perRelay = <String, int>{};
    for (final r in receipts) {
      if (r.coinId != coinId) continue;
      if (_seenReceipts.contains(r.key)) continue;
      if (!r.verify()) continue;
      // Don't reward self-dealing: recipient signing for their own relay.
      if (r.recipient == r.relay) continue;
      final w = _windowFor(r.relay, now);
      final remaining = rules.workCapPerWindow - w.issued;
      if (remaining <= 0) continue;
      final reward =
          rules.workPerReceipt <= remaining ? rules.workPerReceipt : remaining;
      if (reward <= 0) continue;
      w.issued += reward;
      perRelay[r.relay] = (perRelay[r.relay] ?? 0) + reward;
      _seenReceipts.add(r.key);
    }
    final txs = <Map<String, dynamic>>[];
    perRelay.forEach((relay, amount) {
      txs.add(buildGrantTx(
          coinId, adminPriv, relay, amount, 'work:$relay:$now:$amount'));
    });
    return txs;
  }

  /// One-time bootstrap grant for [newcomer], sized by [trustScore] in [0,1]
  /// (anchored trust flow). Returns null if already bootstrapped or score is 0.
  Map<String, dynamic>? bootstrap(String newcomer, double trustScore) {
    if (_bootstrapped.contains(newcomer)) return null;
    final clamped = trustScore < 0 ? 0.0 : (trustScore > 1 ? 1.0 : trustScore);
    final amount = (rules.bootstrapMax * clamped).floor();
    if (amount <= 0) return null;
    _bootstrapped.add(newcomer);
    return buildGrantTx(coinId, adminPriv, newcomer, amount, 'boot:$newcomer');
  }

  _Window _windowFor(String relay, int now) {
    final w = _work[relay];
    if (w == null || now - w.start >= rules.windowSeconds) {
      final fresh = _Window(now);
      _work[relay] = fresh;
      return fresh;
    }
    return w;
  }
}

class _Window {
  final int start;
  int issued = 0;
  _Window(this.start);
}
