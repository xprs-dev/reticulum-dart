/*
 * The cursor an ESP32 can keep (aurora/docs/NOSTR.md, Indexer↔Indexer sync).
 *
 * The property under test is the one that quietly corrupts every naive
 * "sync since N" design: a cursor is only meaningful against the log it came
 * from. Rebuild the log, and a position that looks perfectly valid now points
 * at somebody else's history. The epoch is what turns that into an honest
 * reset instead of a hole in a peer's map that nobody ever notices.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:reticulum/src/services/files/dht/pointer_log.dart';

Uint8List _key(int seed) => Uint8List.fromList(List.filled(32, seed));

Future<ProviderRecord> _rec(RnsIdentity id, int seed, {int? nowMs}) =>
    ProviderRecord.create(
      providerIdentity: id,
      sha256: _key(seed),
      capacity: 3,
      nowMs: nowMs,
    );

void main() {
  late RnsIdentity provider;

  setUp(() async {
    provider = await RnsIdentity.generate();
  });

  test('a peer resumes at a position in OUR log, and gets only what is new',
      () async {
    final log = PointerLog(epoch: 'e1');
    log.add(await _rec(provider, 1));
    final cursor = log.nextSeq - 1; // the peer has read everything so far
    log.add(await _rec(provider, 2));
    log.add(await _rec(provider, 3));

    final fresh = log.since(cursor);
    expect(fresh, hasLength(2), reason: 'only what changed since they read');
    expect(fresh.first.seq, cursor + 1);
  });

  test('removals travel — a dead address must propagate like a new one', () {
    final log = PointerLog(epoch: 'e1');
    log.remove(_key(9), Uint8List.fromList(List.filled(64, 7)));
    final e = log.since(0).single;
    expect(e.isRemoval, isTrue,
        reason: 'an indexer that never propagated removals would hand out dead '
            'addresses for ever');
  });

  test('a cursor from another log is REJECTED, not honoured', () {
    final log = PointerLog(epoch: 'e2');
    expect(log.canResume('e2', 0), isTrue);
    expect(log.canResume('e1', 0), isFalse,
        reason: 'the log was rebuilt underneath them: their position is '
            'meaningless, and a partial answer would leave a hole nobody sees');
  });

  test('a cursor older than what we still hold is a reset, not a partial answer',
      () async {
    final log = PointerLog(epoch: 'e1', maxEntries: 4);
    for (var i = 0; i < 10; i++) {
      log.add(await _rec(provider, i));
    }
    expect(log.length, 4);
    expect(log.oldestSeq, greaterThan(1));
    expect(log.canResume('e1', 1), isFalse, reason: 'compacted away');
    expect(log.canResume('e1', log.nextSeq - 1), isTrue);
  });

  test('re-reading from before the cursor is safe — overlap costs bandwidth, '
      'never correctness', () async {
    final log = PointerLog(epoch: 'e1');
    log.add(await _rec(provider, 1));
    log.add(await _rec(provider, 2));
    final all = log.since(0);
    final overlapping = log.since(0); // the timid peer asks again from zero
    expect(overlapping.map((e) => e.seq), all.map((e) => e.seq),
        reason: 'the merge is idempotent, so asking twice is free — while a gap '
            'costs a pointer nobody knows is missing');
  });

  test('a snapshot is the LIVE map: removals and expiries are already gone',
      () async {
    final log = PointerLog(epoch: 'e1');
    final r1 = await _rec(provider, 1);
    final r2 = await _rec(provider, 2);
    log.add(r1);
    log.add(r2);
    log.remove(r1.sha256, r1.providerPub);

    final snap = log.snapshot();
    expect(snap, hasLength(1));
    expect(snap.single.sha256, r2.sha256);
  });

  test('an expired record never reaches a fresh indexer', () async {
    final log = PointerLog(epoch: 'e1');
    final old = await _rec(provider, 5, nowMs: 1000);
    log.add(old, nowMs: 1000);
    // Long past its 45-minute TTL.
    expect(log.snapshot(nowMs: 1000 + 4000 * 1000), isEmpty);
  });

  test('the log is bounded — it cannot grow for ever', () async {
    final log = PointerLog(epoch: 'e1', maxEntries: 50);
    for (var i = 0; i < 200; i++) {
      log.add(await _rec(provider, i % 200));
    }
    expect(log.length, 50);
  });
}
