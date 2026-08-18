/*
 * SpamPolicy — acceptance control for inbound events at a relay (slice 5).
 *
 * Signature validity is enforced upstream (RelayEventStore.put verifies the
 * Schnorr signature + event id, free). This adds the open-network defences:
 *  - NIP-13 PROOF OF WORK: require the event id to have >= [minPowBits] leading
 *    zero bits (the author burned CPU to mint it). 0 = no PoW required.
 *  - PER-AUTHOR RATE LIMIT: at most [maxEventsPerWindow] events per pubkey per
 *    [window] (sliding).
 *  - SIZE CAPS: reject oversized content / events.
 *  - POSTAGE (optional): a coin-agnostic [postageValidator] callback lets an
 *    event that carries valid consumable postage be accepted even when it would
 *    otherwise be rate-limited, and lets advanced features demand postage
 *    (checked with requirePostage). The callback keeps this file decoupled from
 *    the coin layer; the participation coin supplies it (see
 *    lib/services/coin/postage_gate.dart).
 *
 * Pure/headless. A relay holds one SpamPolicy and calls [check] before storing;
 * an accepted event is recorded against the rate limiter as a side effect.
 */
import 'dart:convert';

import '../../util/nostr_event.dart';

class SpamVerdict {
  final bool accepted;
  final String? reason;
  const SpamVerdict(this.accepted, [this.reason]);
}

class SpamPolicy {
  /// Minimum NIP-13 proof-of-work difficulty (leading zero bits of the id).
  final int minPowBits;

  /// Max events accepted per author within [window].
  final int maxEventsPerWindow;
  final Duration window;

  /// Max UTF-8 bytes of content, and of the whole serialized event.
  final int maxContentBytes;
  final int maxEventBytes;

  /// Optional: returns true if [e] carries valid, consumable postage. Injected
  /// by the coin layer so this file stays coin-agnostic. Null = no postage path.
  final bool Function(NostrEvent e)? postageValidator;

  final Map<String, List<int>> _recent = {}; // pubkey -> accepted timestamps(ms)

  SpamPolicy({
    this.minPowBits = 0,
    this.maxEventsPerWindow = 120,
    this.window = const Duration(minutes: 1),
    this.maxContentBytes = 64 * 1024,
    this.maxEventBytes = 128 * 1024,
    this.postageValidator,
  });

  /// An open, permissive default (no PoW) — good for a trusted community relay.
  factory SpamPolicy.lenient() => SpamPolicy();

  /// A stricter default for a public, open-ingest relay.
  factory SpamPolicy.open({int powBits = 8}) =>
      SpamPolicy(minPowBits: powBits, maxEventsPerWindow: 30);

  /// Decide whether to accept [e]. Set [requirePostage] for advanced-feature
  /// events that must always pay (large files, priority relay, wide broadcast):
  /// they are accepted only if they carry valid postage. Size caps and PoW are
  /// always enforced; valid postage rescues an otherwise rate-limited event
  /// (the postage is the payment, consumed when the relay settles it).
  SpamVerdict check(NostrEvent e, {int? nowMs, bool requirePostage = false}) {
    final id = e.id;
    if (id == null || id.isEmpty) return const SpamVerdict(false, 'no id');

    final contentBytes = utf8.encode(e.content).length;
    if (contentBytes > maxContentBytes) {
      return const SpamVerdict(false, 'content too large');
    }
    final eventBytes = utf8.encode(jsonEncode(e.toJson())).length;
    if (eventBytes > maxEventBytes) {
      return const SpamVerdict(false, 'event too large');
    }

    if (minPowBits > 0 && leadingZeroBits(id) < minPowBits) {
      return SpamVerdict(false, 'insufficient pow (<$minPowBits bits)');
    }

    final hasPostage = postageValidator?.call(e) ?? false;

    // Advanced features must pay regardless of the free allowance.
    if (requirePostage) {
      return hasPostage
          ? const SpamVerdict(true)
          : const SpamVerdict(false, 'postage required');
    }

    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    final cutoff = now - window.inMilliseconds;
    final hits = _recent.putIfAbsent(e.pubkey, () => <int>[])
      ..removeWhere((t) => t < cutoff);
    if (hits.length >= maxEventsPerWindow) {
      // Over the free allowance: accept only if it carries postage (paid path).
      // Paid events don't consume the free quota.
      return hasPostage
          ? const SpamVerdict(true)
          : const SpamVerdict(false, 'rate limited');
    }
    hits.add(now);
    return const SpamVerdict(true);
  }

  /// Forget rate-limit history (e.g. periodic cleanup).
  void reset() => _recent.clear();
}

/// Count leading zero BITS of a lowercase hex string (NIP-13 difficulty).
int leadingZeroBits(String hex) {
  var bits = 0;
  for (var i = 0; i < hex.length; i++) {
    final v = int.tryParse(hex[i], radix: 16);
    if (v == null) break;
    if (v == 0) {
      bits += 4;
      continue;
    }
    bits += 4 - v.bitLength; // leading zeros within this non-zero nibble
    break;
  }
  return bits;
}
