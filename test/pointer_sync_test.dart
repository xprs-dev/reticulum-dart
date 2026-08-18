/*
 * Two indexers, one map (aurora/docs/NOSTR.md, Indexer↔Indexer sync).
 *
 * The rule that makes gossip between them safe: the PROVIDER signs the record,
 * not the indexer handing it over. So we never have to trust the indexer we are
 * talking to — only the maths. A hostile peer can waste our bandwidth; it cannot
 * put a lie in our map, resurrect a dead pointer, or point an address at itself.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:reticulum/src/services/files/dht/pointer_log.dart';
import 'package:reticulum/src/services/files/dht/pointer_sync.dart';

Uint8List _key(int seed) => Uint8List.fromList(List.filled(32, seed));

void main() {
  late RnsIdentity provider;
  late RnsIdentity impostor;

  setUp(() async {
    provider = await RnsIdentity.generate();
    impostor = await RnsIdentity.generate();
  });

  Future<ProviderRecord> rec(RnsIdentity id, int seed, {int? nowMs}) =>
      ProviderRecord.create(
        providerIdentity: id,
        sha256: _key(seed),
        capacity: 3,
        nowMs: nowMs,
      );

  /// A second indexer's map.
  ({
    PointerSyncClient client,
    Map<String, ProviderRecord> map,
  }) mkClient() {
    final map = <String, ProviderRecord>{};
    return (
      map: map,
      client: PointerSyncClient(
        onInsert: (r) async {
          map['${r.sha256}|${r.providerPub}'] = r;
          return true;
        },
        onRemove: (k, p) => map.remove('$k|$p'),
      ),
    );
  }

  test('B learns A\'s pointers in one exchange, and resumes where it stopped',
      () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    log.add(await rec(provider, 1));
    log.add(await rec(provider, 2));

    final b = mkClient();
    final batch = server.answer('A1', 0, max: 10)!;
    final out = await b.client
        .merge('A1', batch.entries, batch.nextSeq, batch.more);

    expect(out.applied, 2);
    expect(out.rejected, 0);
    expect(b.map, hasLength(2));
    expect(out.cursor.epoch, 'A1');

    // A learns something new; B asks again from its cursor and gets ONLY that.
    log.add(await rec(provider, 3));
    final delta = server.answer(out.cursor.epoch, out.cursor.seq, max: 10)!;
    expect(delta.entries, hasLength(1));
  });

  test('a forged record is rejected, never stored, never relayed', () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    log.add(await rec(provider, 7));

    final batch = server.answer('A1', 0)!;
    // The hostile indexer rewrites the envelope to claim it is the provider.
    final tampered = [
      {
        ...batch.entries.first,
        'p': impostor.getPublicKey(),
      }
    ];

    final b = mkClient();
    final out = await b.client.merge('A1', tampered, batch.nextSeq, false);
    expect(out.applied, 0);
    expect(out.rejected, 1);
    expect(b.map, isEmpty,
        reason: 'the provider signed it, not the peer handing it over');
  });

  test('an expired pointer never enters a fresh map', () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    log.add(await rec(provider, 8, nowMs: 1000), nowMs: 1000);

    final batch = server.answer('A1', 0)!;
    final b = mkClient();
    final out = await b.client.merge('A1', batch.entries, batch.nextSeq, false,
        nowMs: 1000 + 4000 * 1000);
    expect(out.applied, 0);
    expect(out.rejected, 1);
  });

  test('removals propagate — a dead address dies everywhere', () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    final r = await rec(provider, 9);
    log.add(r);

    final b = mkClient();
    var batch = server.answer('A1', 0)!;
    var out = await b.client.merge('A1', batch.entries, batch.nextSeq, false);
    expect(b.map, hasLength(1));

    log.remove(r.sha256, r.providerPub);
    batch = server.answer(out.cursor.epoch, out.cursor.seq)!;
    out = await b.client.merge('A1', batch.entries, batch.nextSeq, false);
    expect(out.removed, 1);
    expect(b.map, isEmpty,
        reason: 'an indexer that never propagated removals hands out dead '
            'addresses for ever');
  });

  test('a cursor from a rebuilt log is refused — the reset, not a silent hole',
      () async {
    final log = PointerLog(epoch: 'A2'); // A was rebuilt; new epoch.
    final server = PointerSyncServer(log);
    log.add(await rec(provider, 1));

    expect(server.answer('A1', 5), isNull,
        reason: "B's position points into a history that no longer exists");
    expect(server.answer('A2', 0), isNotNull);
  });

  test('a big log comes in bites — the LoRa indexer case', () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    for (var i = 0; i < 10; i++) {
      log.add(await rec(provider, i));
    }

    final b = mkClient();
    var cursor = const SyncCursor('A1', 0);
    var rounds = 0;
    while (true) {
      final batch = server.answer(cursor.epoch, cursor.seq, max: 3)!;
      final out = await b.client
          .merge('A1', batch.entries, batch.nextSeq, batch.more);
      cursor = out.cursor;
      rounds++;
      if (!out.more) break;
      expect(rounds, lessThan(10), reason: 'it must converge, not spin');
    }
    expect(b.map, hasLength(10));
    expect(rounds, greaterThan(1), reason: 'it really was taken in bites');
  });

  test('a snapshot brings a cold indexer up in one exchange', () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    final r1 = await rec(provider, 1);
    log.add(r1);
    log.add(await rec(provider, 2));
    log.remove(r1.sha256, r1.providerPub); // and one of them died

    final snap = server.snapshot();
    expect(snap, hasLength(1),
        reason: 'a snapshot is the LIVE map: the dead pointer is already gone');
  });
}
