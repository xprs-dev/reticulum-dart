/*
 * RelayProtocol — wire framing for Aurora's NOSTR relay over Reticulum.
 *
 * NIP-01/45/50 semantics, but msgpack-framed (reuse lxmf_msgpack) and carried
 * over an RnsLink instead of a websocket. Each frame is a msgpack array whose
 * first element is the op code:
 *   EVENT    [1, eventMap]                  client -> relay: publish an event
 *   REQ      [2, subId, filterMap]          client -> relay: query/search
 *   COUNT    [3, subId, filterMap]          client -> relay: count matches
 *   STORED   [0x81, ok, reason]             relay -> client: EVENT result
 *   RESULT   [0x82, subId, [eventMap...], eose]  relay -> client: REQ result
 *   COUNTRES [0x83, subId, n]              relay -> client: COUNT result
 *
 * A REQ whose filter carries a `search` field is a NIP-50 full-text query; the
 * relay answers it the same way (RESULT). For slice 2 a REQ returns its whole
 * result set in one RESULT (eose=true) — long-lived subscriptions are a later
 * concern. Event maps are exactly NostrEvent.toJson() / .fromJson().
 */
import 'dart:typed_data';

import '../reticulum/lxmf/lxmf_msgpack.dart';
import '../../util/nostr_event.dart';
import 'relay_event_store.dart';

class RelayOp {
  static const int event = 0x01;
  static const int req = 0x02;
  static const int count = 0x03;
  static const int deposit = 0x04; // store-and-forward: queue a packed LXMF msg
  static const int stored = 0x81;
  static const int result = 0x82;
  static const int countRes = 0x83;
  // Recipient-authorized delete (NON-NIP-09): the p-tagged recipient of a set of
  // events asks the relay to drop them once received, to reclaim space after the
  // DM backup is delivered. [reqPubHex] is the requester's NOSTR pubkey (hex);
  // [sigHex] is a BIP-340 signature by reqPub over sha256(ids.join(',')). The
  // relay drops each id whose stored event carries a `p` tag == reqPub.
  static const int drop = 0x05; // [5, reqPubHex, [ids], sigHex]
  static const int dropRes = 0x85; // [0x85, nDropped]

  // ── Indexer↔Indexer pointer sync (docs/NOSTR.md) ─────────────────────────
  //
  // Indexers exchange ADDRESSES, never content. The records are signed by their
  // providers, so a relaying indexer can neither forge nor resurrect a pointer,
  // and a receiver verifies everything end to end.
  //
  // "What changed since…" takes two cursors, and the POSITION one is normative:
  // an ESP32 back from a reboot has no clock and cannot say "since Tuesday", but
  // it can persist (epoch, seq). Clock skew across a fleet silently drops or
  // duplicates records at the boundary of a time query; a position cannot skew.
  static const int syncReq = 0x06; // [6, epoch|'', sinceSeq, sinceMs, max]
  static const int syncRes = 0x86; // [0x86, epoch, [entries], nextSeq, more]
  static const int syncReset = 0x87; // [0x87, epoch, oldestSeq]
}

/// A decoded relay frame. Only the fields relevant to [op] are populated.
class RelayFrame {
  final int op;
  final String? subId;
  final NostrEvent? event;
  final NostrFilter? filter;
  final List<NostrEvent>? events;
  final bool eose;
  final bool ok;
  final String? reason;
  final int count;
  final String? dest; // DEPOSIT: recipient LXMF delivery dest hash (hex)
  final Uint8List? blob; // DEPOSIT: packed LXMF message
  final String? reqPub; // DROP: requester NOSTR pubkey (hex)
  final List<String>? ids; // DROP: event ids to delete
  final String? sig; // DROP: BIP-340 sig over sha256(ids.join(','))

  // Pointer sync.
  final String? epoch; // whose log this cursor belongs to
  final int sinceSeq; // SYNC_REQ: resume position / SYNC_RESET: oldest we hold
  final int sinceMs; // SYNC_REQ: the time cursor, for nodes that have a clock
  final List<Map<String, dynamic>>? entries; // SYNC_RES: inserts + removals
  final int nextSeq; // SYNC_RES: where to resume next
  final bool more; // SYNC_RES: is there still a backlog?

  const RelayFrame({
    required this.op,
    this.subId,
    this.event,
    this.filter,
    this.events,
    this.eose = false,
    this.ok = false,
    this.reason,
    this.count = 0,
    this.dest,
    this.blob,
    this.reqPub,
    this.ids,
    this.sig,
    this.epoch,
    this.sinceSeq = 0,
    this.sinceMs = 0,
    this.entries,
    this.nextSeq = 0,
    this.more = false,
  });
}

class RelayProtocol {
  // ── Encode ────────────────────────────────────────────────────────────────

  static Uint8List event(NostrEvent e) =>
      msgpackEncode([RelayOp.event, e.toJson()]);

  static Uint8List req(String subId, NostrFilter filter) =>
      msgpackEncode([RelayOp.req, subId, filter.toJson()]);

  static Uint8List count(String subId, NostrFilter filter) =>
      msgpackEncode([RelayOp.count, subId, filter.toJson()]);

  static Uint8List stored(bool ok, [String? reason]) =>
      msgpackEncode([RelayOp.stored, ok, reason]);

  static Uint8List result(String subId, List<NostrEvent> events, bool eose) =>
      msgpackEncode([
        RelayOp.result,
        subId,
        [for (final e in events) e.toJson()],
        eose,
      ]);

  static Uint8List countResult(String subId, int n) =>
      msgpackEncode([RelayOp.countRes, subId, n]);

  /// Store-and-forward: deposit [blob] (a packed LXMF message) for offline
  /// recipient [destHex] (its LXMF delivery dest hash).
  static Uint8List deposit(String destHex, Uint8List blob) =>
      msgpackEncode([RelayOp.deposit, destHex, blob]);

  /// Recipient-authorized delete: ask the relay to drop [ids]. [reqPubHex] is
  /// the requester's NOSTR pubkey and [sigHex] a BIP-340 signature by it over
  /// sha256(ids.join(',')). The relay drops only ids whose event has a `p`
  /// tag == reqPubHex.
  static Uint8List drop(String reqPubHex, List<String> ids, String sigHex) =>
      msgpackEncode([RelayOp.drop, reqPubHex, ids, sigHex]);

  static Uint8List dropResult(int n) => msgpackEncode([RelayOp.dropRes, n]);

  /// "What changed since…". [epoch] + [sinceSeq] is the position cursor (the
  /// only one a clockless node can keep); [sinceMs] is the convenience for a
  /// node that has a clock. Send epoch='' with no cursor to ask for a snapshot.
  static Uint8List syncReq({
    String epoch = '',
    int sinceSeq = 0,
    int sinceMs = 0,
    int max = 64,
  }) =>
      msgpackEncode([RelayOp.syncReq, epoch, sinceSeq, sinceMs, max]);

  /// A bounded, resumable batch. [entries] are encoded ProviderRecords (inserts)
  /// or removals; [nextSeq] is where the asker resumes, and [more] says whether
  /// there is still a backlog — a LoRa-attached indexer takes the same log in
  /// tiny bites over hours, and the cursor makes that free.
  static Uint8List syncRes({
    required String epoch,
    required List<Map<String, dynamic>> entries,
    required int nextSeq,
    required bool more,
  }) =>
      msgpackEncode([RelayOp.syncRes, epoch, entries, nextSeq, more]);

  /// "Your cursor is not from this log (or is older than what I still hold) —
  /// start over." Never a best-effort partial answer: a partial answer leaves a
  /// hole in the asker's map that nobody ever notices.
  static Uint8List syncReset(String epoch, int oldestSeq) =>
      msgpackEncode([RelayOp.syncReset, epoch, oldestSeq]);

  // ── Decode ──────────────────────────────────────────────────────────────

  /// Decode a frame, or null if malformed.
  static RelayFrame? decode(Uint8List bytes) {
    final Object? raw;
    try {
      raw = msgpackDecode(bytes);
    } catch (_) {
      return null;
    }
    if (raw is! List || raw.isEmpty) return null;
    final op = raw[0];
    if (op is! int) return null;
    try {
      switch (op) {
        case RelayOp.event:
          return RelayFrame(op: op, event: _event(raw[1]));
        case RelayOp.deposit:
          return RelayFrame(
            op: op,
            dest: raw[1] as String,
            blob: raw[2] is Uint8List
                ? raw[2] as Uint8List
                : Uint8List.fromList((raw[2] as List).cast<int>()),
          );
        case RelayOp.req:
        case RelayOp.count:
          return RelayFrame(
            op: op,
            subId: raw[1] as String,
            filter: NostrFilter.fromJson(_map(raw[2])),
          );
        case RelayOp.stored:
          return RelayFrame(
            op: op,
            ok: raw[1] == true,
            reason: raw.length > 2 ? raw[2] as String? : null,
          );
        case RelayOp.result:
          final list = (raw[2] as List)
              .map((m) => _event(m))
              .whereType<NostrEvent>()
              .toList();
          return RelayFrame(
            op: op,
            subId: raw[1] as String,
            events: list,
            eose: raw.length > 3 ? raw[3] == true : true,
          );
        case RelayOp.countRes:
          return RelayFrame(
            op: op,
            subId: raw[1] as String,
            count: raw[2] as int,
          );
        case RelayOp.drop:
          return RelayFrame(
            op: op,
            reqPub: raw[1] as String,
            ids: (raw[2] as List).map((e) => e.toString()).toList(),
            sig: raw[3] as String,
          );
        case RelayOp.dropRes:
          return RelayFrame(op: op, count: raw[1] as int);
        case RelayOp.syncReq:
          return RelayFrame(
            op: op,
            epoch: raw[1] as String,
            sinceSeq: (raw[2] as num).toInt(),
            sinceMs: (raw[3] as num).toInt(),
            count: raw.length > 4 ? (raw[4] as num).toInt() : 64,
          );
        case RelayOp.syncRes:
          return RelayFrame(
            op: op,
            epoch: raw[1] as String,
            entries: [
              for (final e in (raw[2] as List))
                if (e is Map) e.cast<String, dynamic>()
            ],
            nextSeq: (raw[3] as num).toInt(),
            more: raw[4] == true,
          );
        case RelayOp.syncReset:
          return RelayFrame(
            op: op,
            epoch: raw[1] as String,
            sinceSeq: (raw[2] as num).toInt(),
          );
        default:
          return null;
      }
    } catch (_) {
      return null;
    }
  }

  static NostrEvent? _event(Object? m) {
    if (m == null) return null;
    return NostrEvent.fromJson(_map(m));
  }

  /// Coerce a msgpack-decoded map (`Map<Object?,Object?>`) to `Map<String,dynamic>`.
  static Map<String, dynamic> _map(Object? m) {
    final src = m as Map;
    return {for (final e in src.entries) e.key.toString(): e.value};
  }
}
