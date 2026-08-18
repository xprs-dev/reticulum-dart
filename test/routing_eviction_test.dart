/*
 * Routing-table liveness eviction — locks the rule that a contact missing
 * [maxFailures] RPCs in a row is evicted, while ANY success resets it. This is
 * what lets lookups stop wasting rounds on dead/unreachable contacts (and is the
 * prerequisite for ever lowering k below the overlay size). A one-off miss — or a
 * lost STORE ack, which the caller deliberately does NOT report as a failure —
 * must never evict a live node.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

Uint8List _id16(int seed) =>
    Uint8List.fromList(List<int>.generate(16, (i) => (seed * 31 + i) & 0xff));

void main() {
  group('RoutingTable liveness eviction', () {
    test('evicts a contact after maxFailures consecutive misses', () async {
      final table = RoutingTable(_id16(0), k: 20);
      final c = DhtContact.ofIdentity(await RnsIdentity.generate());
      table.add(c);
      expect(table.size, 1);

      for (var i = 0; i < RoutingTable.maxFailures - 1; i++) {
        table.recordFailure(c);
      }
      expect(table.size, 1, reason: 'must survive up to the threshold');

      table.recordFailure(c); // the maxFailures-th miss
      expect(table.size, 0, reason: 'evicted after maxFailures in a row');
    });

    test('a success resets the failure count (no eviction)', () async {
      final table = RoutingTable(_id16(0), k: 20);
      final c = DhtContact.ofIdentity(await RnsIdentity.generate());
      table.add(c);

      for (var i = 0; i < RoutingTable.maxFailures - 1; i++) {
        table.recordFailure(c);
      }
      table.recordSuccess(c); // alive again — counter cleared
      for (var i = 0; i < RoutingTable.maxFailures - 1; i++) {
        table.recordFailure(c);
      }
      expect(table.size, 1,
          reason: 'interleaved success must prevent eviction');
    });

    test('recordSuccess on an unknown contact adds it', () async {
      final table = RoutingTable(_id16(0), k: 20);
      table.recordSuccess(DhtContact.ofIdentity(await RnsIdentity.generate()));
      expect(table.size, 1);
    });

    test('recordFailure on an unknown contact is a no-op', () async {
      final table = RoutingTable(_id16(0), k: 20);
      table.recordFailure(DhtContact.ofIdentity(await RnsIdentity.generate()));
      expect(table.size, 0);
    });
  });
}
