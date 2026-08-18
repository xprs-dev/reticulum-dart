/*
 * The pointer log an Indexer syncs from (aurora/docs/NOSTR.md,
 * "Indexer↔Indexer sync — what changed?").
 *
 * Indexers exchange ADDRESSES, never content: the unit is the signed
 * ProviderRecord the DHT already stores. Because the PROVIDER signs it, an
 * Indexer can pass on a third party's record and the receiver still verifies it
 * end to end — a relaying Indexer can neither forge, retarget nor resurrect a
 * pointer. That is what makes gossip between them safe, and what lets a fresh
 * Indexer fill its map from a peer instead of waiting for a thousand phones to
 * re-announce.
 *
 * The log is append-only and carries INSERTIONS AND REMOVALS, because "this
 * address is dead" must propagate as surely as "this address is new" — otherwise
 * every Indexer's map only ever grows and slowly fills with pointers to things
 * that are not there.
 *
 * ── The cursor, and why it is a position and not a time ─────────────────────
 *
 * Every entry gets a `seq`: a strictly increasing counter, local to this log,
 * that never repeats and never goes backwards. A peer resumes at "your log,
 * position N".
 *
 * The sequence is NORMATIVE and time is the convenience, for two reasons:
 *
 *   1. An ESP32 coming back from a reboot has no idea what day it is — no RTC,
 *      no NTP, maybe no route to anything that has either. It cannot say "since
 *      Tuesday". It CAN persist eight bytes.
 *   2. Two Indexers with skewed clocks silently drop or duplicate records at the
 *      boundary of a time query. A position cannot skew: it is not a
 *      measurement, it is a place in one node's log, interpreted only by that
 *      node.
 *
 * `epoch` is what makes `seq` safe, and it is the part naive "sync since N"
 * designs get wrong. A cursor is only meaningful against the log it came from.
 * If this log is truncated, rebuilt or restored, the epoch changes, the peer's
 * cursor becomes meaningless — and we SAY SO (a reset) instead of quietly
 * letting the asker miss everything that happened in between.
 */
import 'dart:typed_data';

import 'dht_core.dart';
import 'provider_record.dart';

/// One change to the map of who-has-what.
class PointerEntry {
  final int seq;

  /// The 32-byte key (a file sha256, or an author's pubkey).
  final Uint8List key;

  /// The provider this entry is about (64-byte pubkey).
  final Uint8List providerPub;

  /// The signed record — null for a REMOVAL ("this address is dead").
  final ProviderRecord? record;

  /// When this node accepted the change. Advisory: a peer with no clock ignores
  /// it entirely, which is exactly why the cursor is [seq].
  final int atMs;

  const PointerEntry({
    required this.seq,
    required this.key,
    required this.providerPub,
    required this.record,
    required this.atMs,
  });

  bool get isRemoval => record == null;
}

/// A bounded, append-only log of pointer changes, with an epoch so a stale
/// cursor can be *detected* rather than silently honoured.
class PointerLog {
  /// How many entries to keep before compacting. A log that is never compacted
  /// is immortal; one that is compacted without telling anybody is a silent gap.
  /// Compaction raises [oldestSeq], and a peer whose cursor predates that is
  /// told to start over.
  final int maxEntries;

  /// Identifies THIS log. Changes whenever the log is rebuilt/truncated/restored
  /// — which is what turns a stale cursor into an honest reset instead of a
  /// silent hole in a peer's map.
  final String epoch;

  final List<PointerEntry> _entries = [];
  int _nextSeq = 1;
  int _oldestSeq = 1;

  PointerLog({required this.epoch, this.maxEntries = 5000});

  int get nextSeq => _nextSeq;
  int get oldestSeq => _oldestSeq;
  int get length => _entries.length;

  /// Record that we now believe [record] (an insert or a refresh).
  int add(ProviderRecord record, {int? nowMs}) => _append(
        key: record.sha256,
        providerPub: record.providerPub,
        record: record,
        nowMs: nowMs,
      );

  /// Record that a provider no longer holds [key] — it failed to serve, or its
  /// record expired. This travels: an Indexer that never propagated removals
  /// would hand out dead addresses for ever.
  int remove(Uint8List key, Uint8List providerPub, {int? nowMs}) => _append(
        key: key,
        providerPub: providerPub,
        record: null,
        nowMs: nowMs,
      );

  int _append({
    required Uint8List key,
    required Uint8List providerPub,
    required ProviderRecord? record,
    int? nowMs,
  }) {
    final seq = _nextSeq++;
    _entries.add(PointerEntry(
      seq: seq,
      key: Uint8List.fromList(key),
      providerPub: Uint8List.fromList(providerPub),
      record: record,
      atMs: nowMs ?? DateTime.now().millisecondsSinceEpoch,
    ));
    _compact();
    return seq;
  }

  void _compact() {
    if (_entries.length <= maxEntries) return;
    final drop = _entries.length - maxEntries;
    _entries.removeRange(0, drop);
    _oldestSeq = _entries.first.seq;
  }

  /// Is [cursor] (from [epoch]) still usable against this log?
  ///
  /// No, when the epoch is not ours (the log was rebuilt underneath them), or
  /// when the position has been compacted away. Both cases are a RESET, never a
  /// best-effort partial answer — a partial answer would leave a hole nobody
  /// ever notices.
  bool canResume(String peerEpoch, int cursor) =>
      peerEpoch == epoch && cursor >= _oldestSeq - 1;

  /// Everything after [cursor], oldest first, at most [max].
  ///
  /// Re-reading from slightly BEFORE a cursor is safe and encouraged: the merge
  /// is idempotent (newest timestamp per (key, provider) wins), so an overlap
  /// costs bandwidth and never correctness — while a gap costs a pointer nobody
  /// knows is missing.
  List<PointerEntry> since(int cursor, {int max = 64}) {
    final out = <PointerEntry>[];
    for (final e in _entries) {
      if (e.seq <= cursor) continue;
      out.add(e);
      if (out.length >= max) break;
    }
    return out;
  }

  /// A filtered snapshot of the LIVE map (expired records already gone), for a
  /// node with no cursor or a rejected one. It is useful within one exchange
  /// instead of after a full announce cycle.
  List<ProviderRecord> snapshot({int max = 256, int? nowMs}) {
    final live = <String, ProviderRecord>{};
    for (final e in _entries) {
      final id = dhtHex(e.key) + dhtHex(e.providerPub);
      if (e.isRemoval) {
        live.remove(id);
      } else if (!e.record!.isExpired(nowMs)) {
        live[id] = e.record!;
      }
    }
    return live.values.take(max).toList();
  }
}
