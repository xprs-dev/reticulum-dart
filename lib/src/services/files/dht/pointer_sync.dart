/*
 * Indexer↔Indexer pointer sync — the two halves that talk (docs/NOSTR.md).
 *
 * Serving:  answer "what changed since (epoch, seq)" from the pointer log, in
 *           bounded resumable batches, and say RESET rather than hand back a
 *           partial answer against a cursor we cannot honour.
 * Merging:  take a peer's batch, VERIFY every record against the provider that
 *           signed it, and apply it idempotently.
 *
 * Indexer-to-indexer traffic is fast and wired, so this is where the load should
 * sit: the phones announce once, and the Indexers spread it among themselves.
 * Battery-powered leaves are never sync partners — they announce, they are
 * indexed, they are left alone. That asymmetry is the whole reason the role
 * exists.
 */
import 'dart:typed_data';

import 'dht_core.dart';
import 'pointer_log.dart';
import 'provider_record.dart';

/// A cursor into ONE peer's log. Eight bytes and a name — small enough that an
/// ESP32 with no clock can persist one per peer across a reboot, which is the
/// entire reason the cursor is a position and not a time.
class SyncCursor {
  final String epoch;
  final int seq;
  const SyncCursor(this.epoch, this.seq);
  static const SyncCursor none = SyncCursor('', 0);

  Map<String, dynamic> toMap() => {'e': epoch, 's': seq};
  static SyncCursor fromMap(Map? m) => m == null
      ? none
      : SyncCursor('${m['e'] ?? ''}', (m['s'] as num?)?.toInt() ?? 0);
}

/// What a sync produced.
class SyncOutcome {
  final int applied;
  final int rejected; // failed verification — a peer may lie; the maths cannot
  final int removed;
  final SyncCursor cursor;
  final bool more;
  final bool wasReset;

  const SyncOutcome({
    this.applied = 0,
    this.rejected = 0,
    this.removed = 0,
    this.cursor = SyncCursor.none,
    this.more = false,
    this.wasReset = false,
  });
}

/// The serving half: turn a request into either a batch or an honest reset.
class PointerSyncServer {
  final PointerLog log;
  const PointerSyncServer(this.log);

  /// Answer "what changed since". Returns null when the cursor cannot be
  /// honoured — the caller then sends SYNC_RESET(epoch, oldestSeq), and the
  /// asker starts from a snapshot instead of quietly missing everything in
  /// between. That silent hole is the bug this design exists to avoid.
  ({List<Map<String, dynamic>> entries, int nextSeq, bool more})? answer(
    String peerEpoch,
    int cursor, {
    int max = 64,
  }) {
    if (!log.canResume(peerEpoch, cursor)) return null;
    final batch = log.since(cursor, max: max);
    final next = batch.isEmpty ? log.nextSeq - 1 : batch.last.seq;
    final more = batch.length >= max && next < log.nextSeq - 1;
    return (
      entries: [for (final e in batch) _encodeEntry(e)],
      nextSeq: next,
      more: more,
    );
  }

  /// A filtered snapshot of the live map, for a peer with no cursor or a
  /// rejected one — useful within one exchange, instead of after a full announce
  /// cycle.
  List<Map<String, dynamic>> snapshot({int max = 256}) => [
        for (final r in log.snapshot(max: max))
          {'k': r.sha256, 'p': r.providerPub, 'r': r.encode()}
      ];

  static Map<String, dynamic> _encodeEntry(PointerEntry e) => {
        'q': e.seq,
        'k': e.key,
        'p': e.providerPub,
        // A removal carries no record: "this address is dead" needs no proof of
        // the address, only of who is saying so — and we already know that, it is
        // the peer we are talking to. It is a HINT, and a wrong one costs a
        // re-publish (every 30 min), never a lost file.
        if (e.record != null) 'r': e.record!.encode(),
      };
}

/// The merging half: apply a peer's batch to our own map. Nothing is trusted.
class PointerSyncClient {
  /// Called for a verified insert. Return true if it was actually stored.
  final Future<bool> Function(ProviderRecord record) onInsert;

  /// Called for a removal ("this provider no longer holds this key").
  final void Function(Uint8List key, Uint8List providerPub) onRemove;

  const PointerSyncClient({required this.onInsert, required this.onRemove});

  /// Merge one SYNC_RES batch.
  ///
  /// Every record is verified against the provider that signed it BEFORE it
  /// enters our map. That is what makes gossip between indexers safe: we never
  /// have to trust the indexer we are talking to, only the maths. An unsigned,
  /// forged or expired record is dropped and counted — not relayed onward.
  Future<SyncOutcome> merge(
    String epoch,
    List<Map<String, dynamic>> entries,
    int nextSeq,
    bool more, {
    int? nowMs,
  }) async {
    var applied = 0;
    var rejected = 0;
    var removed = 0;

    for (final e in entries) {
      final rawRec = e['r'];
      final key = _bytes(e['k']);
      final pub = _bytes(e['p']);
      if (key == null || pub == null) {
        rejected++;
        continue;
      }
      if (rawRec == null) {
        onRemove(key, pub);
        removed++;
        continue;
      }
      final encoded = _bytes(rawRec);
      if (encoded == null) {
        rejected++;
        continue;
      }
      final rec = ProviderRecord.decode(encoded);
      if (rec == null || rec.isExpired(nowMs)) {
        rejected++;
        continue;
      }
      // The provider signed it, not the peer that just handed it to us. So a
      // relaying indexer can neither forge a pointer nor resurrect a dead one.
      if (!await rec.verify()) {
        rejected++;
        continue;
      }
      if (!_eq(rec.providerPub, pub) || !_eq(rec.sha256, key)) {
        rejected++; // it does not even say what the envelope claims it says
        continue;
      }
      if (await onInsert(rec)) applied++;
    }

    return SyncOutcome(
      applied: applied,
      rejected: rejected,
      removed: removed,
      cursor: SyncCursor(epoch, nextSeq),
      more: more,
    );
  }

  static Uint8List? _bytes(Object? v) {
    if (v is Uint8List) return v;
    if (v is List) return Uint8List.fromList(v.cast<int>());
    return null;
  }

  static bool _eq(Uint8List a, Uint8List b) =>
      a.length == b.length && dhtHex(a) == dhtHex(b);
}
