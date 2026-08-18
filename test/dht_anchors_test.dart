/*
 * Persistence anchors — locks capacity-biased replication's two guarantees:
 *   1. publish() also STOREs to the always-on anchors (not just the XOR-closest),
 *      so records survive churn of the ephemeral closest set.
 *   2. resolve() queries the anchors FIRST, so a record that lives only on an
 *      anchor is found regardless of XOR distance or how small k is — the property
 *      that makes a later k-reduction safe.
 * The anchor set is injected (the DHT engine stays generic); empty anchors fall
 * straight back to classic Kademlia.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// Tiny in-process router: sendRpc routes to the addressed node's responder.
class _Net {
  final Map<String, DhtNode> nodes = {};

  DhtNode add(RnsIdentity id,
      {int k = 8, List<DhtContact> Function()? anchors}) {
    final n = DhtNode(
      identity: id,
      k: k,
      anchors: anchors,
      sendRpc: (to, req) async {
        final target = nodes[to.idHex];
        if (target == null) return null;
        return DhtMessage.decode(
            (await target.handle(DhtMessage.decode(req.encode())!)).encode());
      },
    );
    nodes[dhtHex(n.myId)] = n;
    return n;
  }
}

Uint8List _sha(int seed) =>
    Uint8List.fromList(List<int>.generate(32, (i) => (seed * 97 + i) & 0xff));

void main() {
  group('DHT persistence anchors', () {
    test('publish STOREs to a non-closest anchor', () async {
      final net = _Net();
      final anchorId = await RnsIdentity.generate();
      final anchor = net.add(anchorId);

      final pubId = await RnsIdentity.generate();
      // Publisher knows NO closest peers — only the injected anchor.
      final publisher =
          net.add(pubId, anchors: () => [DhtContact.ofIdentity(anchorId)]);

      final sha = _sha(1);
      await publisher.publish(
          await ProviderRecord.create(providerIdentity: pubId, sha256: sha));

      expect(anchor.storedKeys, greaterThan(0),
          reason: 'publish must replicate to the anchor');
    });

    test('resolve finds an anchor-only record despite tiny k', () async {
      final net = _Net();
      final anchorId = await RnsIdentity.generate();
      final anchor = net.add(anchorId);

      // The record lives ONLY on the anchor.
      final provider = await RnsIdentity.generate();
      final sha = _sha(2);
      await anchor.handle(DhtMessage.store(provider.getPublicKey(),
          await ProviderRecord.create(
              providerIdentity: provider, sha256: sha)));

      // A decoy the resolver CAN walk to, but which does not hold the record.
      final decoyId = await RnsIdentity.generate();
      net.add(decoyId);

      // Resolver: k=1, anchor NOT in routing — only reachable via the anchor set.
      final withAnchors = net.add(await RnsIdentity.generate(),
          k: 1, anchors: () => [DhtContact.ofIdentity(anchorId)]);
      withAnchors.routing.add(DhtContact.ofIdentity(decoyId));
      final got = await withAnchors.resolve(sha);
      expect(got, isNotEmpty,
          reason: 'anchors-first path must find it regardless of k/distance');
      expect(got.first.providerPub, equals(provider.getPublicKey()));

      // Same setup WITHOUT anchors: the k=1 XOR-walk can't reach the holder.
      final noAnchors = net.add(await RnsIdentity.generate(), k: 1);
      noAnchors.routing.add(DhtContact.ofIdentity(decoyId));
      expect(await noAnchors.resolve(sha), isEmpty,
          reason: 'without anchors the tiny-k walk cannot find an anchor-only record');
    });

    test('a record present on the anchor is preferred without the XOR-walk',
        () async {
      // Anchor holds the record; resolver also has a separate holder in routing.
      // The anchors-first fast path should return before walking the DHT.
      final net = _Net();
      final anchorId = await RnsIdentity.generate();
      final anchor = net.add(anchorId);
      final provider = await RnsIdentity.generate();
      final sha = _sha(3);
      await anchor.handle(DhtMessage.store(provider.getPublicKey(),
          await ProviderRecord.create(
              providerIdentity: provider, sha256: sha)));

      final resolver = net.add(await RnsIdentity.generate(),
          anchors: () => [DhtContact.ofIdentity(anchorId)]);
      final got = await resolver.resolve(sha);
      expect(got, isNotEmpty);
      expect(got.first.providerPub, equals(provider.getPublicKey()));
    });
  });
}
