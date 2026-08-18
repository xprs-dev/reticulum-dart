/*
 * postage_gate — how postage rides on a message, and validators a relay's spam
 * policy can call to accept paid traffic above the free tier.
 *
 * Postage travels as a tag ["postage", base64url(json)]. Two API layers:
 *   - HOST-NEUTRAL (tags): readPostageFromTags / postageValidatorForTags work on
 *     a plain List<List<String>>, so a host with its OWN event type can integrate
 *     without adopting this library's NostrEvent.
 *   - CONVENIENCE (NostrEvent): readPostage / makePostageValidator for hosts that
 *     use the vendored NostrEvent directly.
 *
 * A relay wires the validator into its spam control so that events over the free
 * rate limit are still accepted if they carry valid postage payable to this
 * relay (and advanced features can be made to require it). The postage is settled
 * and double-spend-checked later when the relay redeems it on the ATM chain.
 *
 * Pure/headless: postage + coin_keyset (+ nostr_event for the convenience layer).
 */
import 'dart:convert';

import 'coin_keyset.dart';
import '../../util/nostr_event.dart';
import 'postage.dart';

const String kPostageTag = 'postage';

/// The event tag carrying [postage]: ["postage", base64url(json)].
List<String> postageTag(Postage postage) =>
    [kPostageTag, base64Url.encode(utf8.encode(jsonEncode(postage.toJson())))];

// ── host-neutral (tags) ──────────────────────────────────────────────────────

/// Extract postage from a tag list, or null if absent/malformed.
Postage? readPostageFromTags(List<List<String>> tags) {
  for (final t in tags) {
    if (t.length >= 2 && t[0] == kPostageTag) {
      try {
        return Postage.fromJson(
            jsonDecode(utf8.decode(base64Url.decode(t[1]))));
      } catch (_) {
        return null;
      }
    }
  }
  return null;
}

/// A validator over a tag list: true when the tags carry authentic postage of at
/// least [minAmount], payable to this [relayPub], for the [coinId]/[keyset] coin.
bool Function(List<List<String>> tags) postageValidatorForTags({
  required String coinId,
  required CoinKeyset keyset,
  required String relayPub,
  int minAmount = 1,
}) {
  return (List<List<String>> tags) {
    final postage = readPostageFromTags(tags);
    if (postage == null) return false;
    if (postage.amount < minAmount) return false;
    return Postage.verify(coinId, postage, keyset, relayPub);
  };
}

// ── convenience (vendored NostrEvent) ────────────────────────────────────────

/// Extract postage from an event's tags, or null if absent/malformed.
Postage? readPostage(NostrEvent e) => readPostageFromTags(e.tags);

/// Build a `bool Function(NostrEvent)` validator (e.g. for a SpamPolicy that
/// takes a postage callback). Wraps [postageValidatorForTags].
bool Function(NostrEvent) makePostageValidator({
  required String coinId,
  required CoinKeyset keyset,
  required String relayPub,
  int minAmount = 1,
}) {
  final inner = postageValidatorForTags(
      coinId: coinId, keyset: keyset, relayPub: relayPub, minAmount: minAmount);
  return (NostrEvent e) => inner(e.tags);
}
