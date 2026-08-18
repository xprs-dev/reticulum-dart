/*
 * Locks the DHT publish fix: a provider must keep its OWN provider record locally
 * even when it has peers, so content it holds stays discoverable when querying it
 * directly — even if every replication STORE to the k-closest peers fails. This
 * was the root cause of "resolved 0 providers" between two meshed devices: the
 * publisher replicated to nobody (flaky paths) AND kept nothing.
 */
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  group('DhtNode.publish early-stop (lost-ack fix)', () {
    test('returns at targetReplicas without blocking on a hung contact',
        () async {
      final me = await RnsIdentity.generate();
      final hung = DhtContact.ofIdentity(await RnsIdentity.generate());
      // STORE to the hung contact NEVER answers (models an ACK that never comes
      // back); FIND always answers so iterativeFindNode itself doesn't stall.
      final node = DhtNode(
        identity: me,
        k: 20, // cover all seeded contacts so >= targetReplicas healthy are tried
        sendRpc: (to, req) async {
          if (req.op == DhtOp.store) {
            if (to.idHex == hung.idHex) return Completer<DhtMessage?>().future;
            return DhtMessage.storeOk(to.publicKey, true);
          }
          return DhtMessage.nodes(to.publicKey, const []);
        },
      );
      // Enough healthy peers to reach the target, plus the black-hole contact.
      for (var i = 0; i < DhtNode.targetReplicas + 2; i++) {
        node.routing.add(DhtContact.ofIdentity(await RnsIdentity.generate()));
      }
      node.routing.add(hung);

      final sha = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final rec = await ProviderRecord.create(providerIdentity: me, sha256: sha);
      // Without early-stop this would hang on the never-completing STORE; the
      // timeout makes the failure mode a test failure, not an infinite wait.
      final holders =
          await node.publish(rec).timeout(const Duration(seconds: 5));
      expect(holders, greaterThanOrEqualTo(DhtNode.targetReplicas),
          reason: 'publish confirms enough replicas and returns');
    });
  });

  group('DhtNode.demoteProvider (dead-holder pruning)', () {
    test('a demoted provider is no longer returned by a local resolve',
        () async {
      final me = await RnsIdentity.generate();
      final provider = await RnsIdentity.generate();
      // Holder with the provider's record in its local store, no outbound peers.
      final node = DhtNode(identity: me, sendRpc: (to, req) async => null);
      final sha = Uint8List.fromList(List<int>.generate(32, (i) => i * 3));
      await node.handle(DhtMessage.store(provider.getPublicKey(),
          await ProviderRecord.create(
              providerIdentity: provider, sha256: sha)));

      expect((await node.resolve(sha)), isNotEmpty,
          reason: 'record is present before demotion');
      expect(node.providersDemoted, 0);

      final removed = node.demoteProvider(sha, provider.getPublicKey());
      expect(removed, isTrue);
      expect(node.providersDemoted, 1);
      expect(await node.resolve(sha), isEmpty,
          reason: 'a fetch-failed provider must not be handed out again');

      // Demoting something we do not hold is a harmless no-op.
      expect(node.demoteProvider(sha, provider.getPublicKey()), isFalse);
      expect(node.providersDemoted, 1);
    });
  });

  group('DhtNode.publish keeps the publisher authoritative', () {
    test('keeps its own record when replication STOREs all fail', () async {
      final me = await RnsIdentity.generate();
      // sendRpc always fails (no peer is reachable) — models flaky paths.
      final node = DhtNode(identity: me, sendRpc: (to, req) async => null);
      // Give it peers so it's NOT the isolated-network case.
      for (var i = 0; i < 3; i++) {
        node.routing.add(DhtContact.ofIdentity(await RnsIdentity.generate()));
      }
      expect(node.storedKeys, 0);

      final sha = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final rec = await ProviderRecord.create(providerIdentity: me, sha256: sha);
      final holders = await node.publish(rec);

      expect(holders, greaterThanOrEqualTo(1),
          reason: 'the publisher counts as a holder of its own record');
      expect(node.storedKeys, 1, reason: 'record kept locally despite failed STOREs');

      // Querying this node (as a resolver would) returns the record.
      final got = await node.resolve(sha);
      expect(got, isNotEmpty);
      expect(got.first.sha256, equals(sha));
    });

    test('a resolver gets the record by querying the holder directly', () async {
      // Two nodes: holder publishes, resolver has only the holder in its routing
      // and must learn the provider by asking it (FIND_VALUE).
      final holderId = await RnsIdentity.generate();
      final resolverId = await RnsIdentity.generate();
      late DhtNode holder;
      late DhtNode resolver;
      holder = DhtNode(
          identity: holderId,
          sendRpc: (to, req) async => null); // holder needs no outbound peers
      resolver = DhtNode(
        identity: resolverId,
        // The resolver's RPC routes straight to the holder's responder.
        sendRpc: (to, req) async =>
            DhtMessage.decode((await holder.handle(req)).encode()),
      );
      resolver.routing.add(DhtContact.ofIdentity(holderId));

      final sha = Uint8List.fromList(List<int>.generate(32, (i) => 255 - i));
      final rec =
          await ProviderRecord.create(providerIdentity: holderId, sha256: sha);
      await holder.publish(rec);

      final got = await resolver.resolve(sha);
      expect(got, isNotEmpty, reason: 'resolver must find the holder by asking it');
      expect(got.first.providerIdentity.hexHash, holderId.hexHash);
    });
  });
}
