/*
 * NOSTR relay wire codec (NIP-01) — pure, transport-agnostic.
 *
 * The public NOSTR network frames its relay protocol as JSON arrays over a
 * WebSocket ("REQ"/"EVENT"/"EOSE"/"OK"/...). Aurora also carries the SAME logical
 * messages over Reticulum (msgpack ops, see relay_protocol.dart) and in-process
 * (the local RelayEventStore). This file is the ONE place that speaks the JSON
 * wire, so it can be unit-tested with zero sockets and reused by every WebSocket
 * transport (public relays AND the device's own local wss server).
 */
import 'dart:convert';

import '../../util/nostr_event.dart';
import 'relay_event_store.dart' show NostrFilter;

/// A decoded inbound relay message.
sealed class NostrRelayMessage {
  const NostrRelayMessage();
}

/// `["EVENT", subId, event]` — an event answering a subscription.
class NostrEventMsg extends NostrRelayMessage {
  final String subId;
  final NostrEvent event;
  const NostrEventMsg(this.subId, this.event);
}

/// `["EOSE", subId]` — end of stored events for a subscription (NIP-15).
class NostrEoseMsg extends NostrRelayMessage {
  final String subId;
  const NostrEoseMsg(this.subId);
}

/// `["OK", eventId, accepted, message]` — publish acknowledgement (NIP-20).
class NostrOkMsg extends NostrRelayMessage {
  final String eventId;
  final bool accepted;
  final String message;
  const NostrOkMsg(this.eventId, this.accepted, this.message);
}

/// `["NOTICE", message]` — human-readable relay notice.
class NostrNoticeMsg extends NostrRelayMessage {
  final String message;
  const NostrNoticeMsg(this.message);
}

/// `["CLOSED", subId, message]` — relay closed a subscription (NIP-01).
class NostrClosedMsg extends NostrRelayMessage {
  final String subId;
  final String message;
  const NostrClosedMsg(this.subId, this.message);
}

/// `["REQ", subId, filter...]` — a subscription request (server-side ingest).
class NostrReqMsg extends NostrRelayMessage {
  final String subId;
  final List<NostrFilter> filters;
  const NostrReqMsg(this.subId, this.filters);
}

/// `["CLOSE", subId]` — cancel a subscription (server-side ingest).
class NostrCloseMsg extends NostrRelayMessage {
  final String subId;
  const NostrCloseMsg(this.subId);
}

/// A client `["EVENT", event]` publish (server-side ingest).
class NostrPublishMsg extends NostrRelayMessage {
  final NostrEvent event;
  const NostrPublishMsg(this.event);
}

class NostrWire {
  // ── Client → relay framing ────────────────────────────────────────────────

  /// `["REQ", subId, filter1, filter2, ...]`.
  static String req(String subId, List<NostrFilter> filters) =>
      jsonEncode(['REQ', subId, ...filters.map((f) => f.toJson())]);

  /// `["EVENT", event]` — publish an event.
  static String event(NostrEvent e) => jsonEncode(['EVENT', e.toJson()]);

  /// `["CLOSE", subId]`.
  static String close(String subId) => jsonEncode(['CLOSE', subId]);

  // ── Relay → client framing (used by the local wss server) ─────────────────

  static String eventFor(String subId, NostrEvent e) =>
      jsonEncode(['EVENT', subId, e.toJson()]);
  static String eose(String subId) => jsonEncode(['EOSE', subId]);
  static String ok(String eventId, bool accepted, [String message = '']) =>
      jsonEncode(['OK', eventId, accepted, message]);
  static String notice(String message) => jsonEncode(['NOTICE', message]);
  static String closed(String subId, [String message = '']) =>
      jsonEncode(['CLOSED', subId, message]);

  // ── Decode any frame (both directions) ────────────────────────────────────

  /// Parse a raw JSON frame into a typed message, or null if malformed /
  /// unrecognised. Never throws — a relay can send anything.
  static NostrRelayMessage? decode(String raw) {
    Object? j;
    try {
      j = jsonDecode(raw);
    } catch (_) {
      return null;
    }
    if (j is! List || j.isEmpty || j[0] is! String) return null;
    final type = j[0] as String;
    try {
      switch (type) {
        case 'EVENT':
          // Relay→client: ["EVENT", subId, ev]; Client→relay: ["EVENT", ev].
          if (j.length >= 3 && j[1] is String) {
            return NostrEventMsg(
                j[1] as String, NostrEvent.fromJson(_map(j[2])));
          }
          if (j.length >= 2 && j[1] is Map) {
            return NostrPublishMsg(NostrEvent.fromJson(_map(j[1])));
          }
          return null;
        case 'EOSE':
          return j.length >= 2 ? NostrEoseMsg('${j[1]}') : null;
        case 'OK':
          if (j.length >= 3) {
            return NostrOkMsg('${j[1]}', j[2] == true,
                j.length >= 4 ? '${j[3]}' : '');
          }
          return null;
        case 'NOTICE':
          return j.length >= 2 ? NostrNoticeMsg('${j[1]}') : null;
        case 'CLOSED':
          return j.length >= 2
              ? NostrClosedMsg('${j[1]}', j.length >= 3 ? '${j[2]}' : '')
              : null;
        case 'REQ':
          if (j.length >= 2 && j[1] is String) {
            final filters = <NostrFilter>[];
            for (var i = 2; i < j.length; i++) {
              if (j[i] is Map) filters.add(NostrFilter.fromJson(_map(j[i])));
            }
            return NostrReqMsg(j[1] as String, filters);
          }
          return null;
        case 'CLOSE':
          return j.length >= 2 ? NostrCloseMsg('${j[1]}') : null;
        default:
          return null;
      }
    } catch (_) {
      return null;
    }
  }

  static Map<String, dynamic> _map(Object? o) =>
      (o as Map).map((k, v) => MapEntry(k.toString(), v));

  /// In-memory NIP-01 filter match — used to LIVE-push a freshly-stored event to
  /// open subscriptions (the store's own query is SQL and authoritative for the
  /// backlog; this is the equivalent for a single new event).
  static bool matches(NostrFilter f, NostrEvent e) {
    if (f.ids != null && !f.ids!.contains(e.id)) return false;
    if (f.authors != null && !f.authors!.contains(e.pubkey)) return false;
    if (f.kinds != null && !f.kinds!.contains(e.kind)) return false;
    if (f.since != null && e.createdAt < f.since!) return false;
    if (f.until != null && e.createdAt > f.until!) return false;
    if (f.tags != null) {
      for (final cond in f.tags!.entries) {
        final want = cond.value;
        final has = e.tags.any((t) =>
            t.length >= 2 && t[0] == cond.key && want.contains(t[1]));
        if (!has) return false;
      }
    }
    return true;
  }
}
