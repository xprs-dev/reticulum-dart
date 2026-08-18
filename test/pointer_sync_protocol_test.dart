/*
 * The SYNC frames on the wire (aurora/docs/NOSTR.md).
 *
 * The pointer log and the merge are tested elsewhere; what is tested here is the
 * conversation: a request carries a position, an answer carries a bounded batch
 * and the place to resume, and a cursor we cannot honour comes back as an honest
 * RESET — never as a partial answer, which would leave a hole in the asker's map
 * that nobody would ever notice.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:reticulum/src/services/files/dht/pointer_log.dart';
import 'package:reticulum/src/services/files/dht/pointer_sync.dart';

Uint8List _key(int seed) => Uint8List.fromList(List.filled(32, seed));

void main() {
  late RnsIdentity provider;

  setUp(() async => provider = await RnsIdentity.generate());

  Future<ProviderRecord> rec(int seed) => ProviderRecord.create(
        providerIdentity: provider,
        sha256: _key(seed),
        capacity: 3,
      );

  test('SYNC_REQ carries the position cursor, not a promise about the clock',
      () {
    final f = RelayProtocol.decode(
        RelayProtocol.syncReq(epoch: 'A1', sinceSeq: 42, max: 16))!;
    expect(f.op, RelayOp.syncReq);
    expect(f.epoch, 'A1');
    expect(f.sinceSeq, 42);
    expect(f.count, 16);
    expect(f.sinceMs, 0,
        reason: 'a clockless node sends no time, and is not penalised for it');
  });

  test('a full exchange: request → batch → merge → resume', () async {
    final log = PointerLog(epoch: 'A1');
    final server = PointerSyncServer(log);
    log.add(await rec(1));
    log.add(await rec(2));

    // B asks from zero.
    final req = RelayProtocol.decode(RelayProtocol.syncReq(epoch: 'A1'))!;
    final answer = server.answer(req.epoch!, req.sinceSeq, max: req.count)!;
    final wire = RelayProtocol.syncRes(
      epoch: log.epoch,
      entries: answer.entries,
      nextSeq: answer.nextSeq,
      more: answer.more,
    );

    final res = RelayProtocol.decode(wire)!;
    expect(res.op, RelayOp.syncRes);
    expect(res.entries, hasLength(2));
    expect(res.more, isFalse);

    final map = <String, ProviderRecord>{};
    final client = PointerSyncClient(
      onInsert: (r) async {
        map['${r.sha256}'] = r;
        return true;
      },
      onRemove: (k, p) => map.remove('$k'),
    );
    final out = await client.merge(
        res.epoch!, res.entries!, res.nextSeq, res.more);

    expect(out.applied, 2);
    expect(map, hasLength(2));
    expect(out.cursor.epoch, 'A1');
    expect(out.cursor.seq, res.nextSeq);
  });

  test('a stale cursor comes back as a RESET, and the asker starts over', () {
    final log = PointerLog(epoch: 'A2'); // rebuilt since B last spoke to us
    final server = PointerSyncServer(log);

    expect(server.answer('A1', 7), isNull);

    final reset =
        RelayProtocol.decode(RelayProtocol.syncReset(log.epoch, log.oldestSeq))!;
    expect(reset.op, RelayOp.syncReset);
    expect(reset.epoch, 'A2');
    expect(reset.sinceSeq, log.oldestSeq);
  });

  test('a peer with no map answers RESET with an empty epoch — "nothing to give"',
      () {
    final f = RelayProtocol.decode(RelayProtocol.syncReset('', 0))!;
    expect(f.op, RelayOp.syncReset);
    expect(f.epoch, isEmpty);
  });
}
