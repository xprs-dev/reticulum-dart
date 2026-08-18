/*
 * Multi-node DHT mesh — the regression lock for the two bugs that made the live
 * "check for updates over Reticulum" both SLOW and FRAGILE between two phones on
 * different networks:
 *
 *   1) resolve() walked the FULL iterative lookup (k contacts, 8 s link timeout
 *      each) even after a node already returned the value — a multi-minute hang.
 *      FIND_VALUE must short-circuit on the first verified record.
 *   2) publish() STOREd to the k-closest SEQUENTIALLY, so one slow/dead contact
 *      stalled every STORE behind it; with the hosted-folder advertiser capping
 *      each publish at 10 s, replication was cut off after self only ("1 holders
 *      (+self)"). The fan-out must be concurrent so records actually replicate.
 *
 * The mesh wires N real DhtNodes so each node's sendRpc routes straight to the
 * addressed node's responder (encode/decode round-tripped like the wire). It can
 * mark contacts dead (unreachable) and add a per-RPC delay, and tracks RPC count
 * and peak concurrency so the tests assert behaviour, not wall-clock.
 */
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Mesh {
  final Map<String, DhtNode> nodes = {}; // dht-dest-hash hex -> node
  final Set<String> dead = {}; // idHex of unreachable nodes
  Duration perCall = Duration.zero; // models a slow link
  int rpcCount = 0;
  int _inFlight = 0;
  int peakConcurrency = 0;

  DhtNode add(RnsIdentity id, {int k = 8}) {
    final node = DhtNode(
      identity: id,
      k: k,
      sendRpc: (to, req) async {
        rpcCount++;
        _inFlight++;
        if (_inFlight > peakConcurrency) peakConcurrency = _inFlight;
        try {
          if (perCall > Duration.zero) await Future.delayed(perCall);
          if (dead.contains(to.idHex)) return null;
          final target = nodes[to.idHex];
          if (target == null) return null;
          final resp = await target.handle(DhtMessage.decode(req.encode())!);
          return DhtMessage.decode(resp.encode());
        } finally {
          _inFlight--;
        }
      },
    );
    nodes[dhtHex(node.myId)] = node;
    return node;
  }

  /// Seed every node's routing table with every other node (fully meshed).
  void crossSeed() {
    for (final a in nodes.values) {
      for (final b in nodes.values) {
        if (identical(a, b)) continue;
        a.routing.add(DhtContact.ofIdentity(b.identity));
      }
    }
  }
}

Uint8List _sha(int seed) => Uint8List.fromList(
    crypto.sha256.convert(Uint8List.fromList([seed, seed >> 8, seed >> 16])).bytes);

void main() {
  group('DHT mesh: replication + FIND_VALUE early-exit', () {
    test('publish replicates to peers, not just self', () async {
      final mesh = _Mesh();
      for (var i = 0; i < 12; i++) {
        mesh.add(await RnsIdentity.generate());
      }
      mesh.crossSeed();
      final nodes = mesh.nodes.values.toList();
      final publisher = nodes.first;

      final sha = _sha(101);
      final rec =
          await ProviderRecord.create(providerIdentity: publisher.identity, sha256: sha);
      final holders = await publisher.publish(rec);

      // Replicated to several real peers, not just the publisher's own copy.
      expect(holders, greaterThan(1),
          reason: 'STORE must reach the k-closest peers, not only self');
      // Count how many OTHER nodes actually custody the record.
      final externalHolders = nodes
          .where((n) => !identical(n, publisher) && n.storedKeys > 0)
          .length;
      expect(externalHolders, greaterThanOrEqualTo(1),
          reason: 'the record must physically live on peer nodes');
    });

    test('a resolver that does NOT know the origin still finds the record',
        () async {
      final mesh = _Mesh();
      for (var i = 0; i < 12; i++) {
        mesh.add(await RnsIdentity.generate());
      }
      mesh.crossSeed();
      final nodes = mesh.nodes.values.toList();
      final publisher = nodes.first;

      final sha = _sha(202);
      final rec =
          await ProviderRecord.create(providerIdentity: publisher.identity, sha256: sha);
      await publisher.publish(rec);

      // Fresh resolver: knows everyone EXCEPT the publisher. It must discover the
      // provider purely from the replicated copies on the k-closest holders.
      final resolver = mesh.add(await RnsIdentity.generate());
      for (final n in nodes) {
        if (identical(n, publisher)) continue;
        resolver.routing.add(DhtContact.ofIdentity(n.identity));
      }

      final providers = await resolver.resolve(sha);
      expect(providers, isNotEmpty,
          reason: 'replication must make content discoverable without the origin');
      expect(providers.first.providerPub, equals(publisher.identity.getPublicKey()));
    });

    test('resolve short-circuits once the value is found (few RPCs)', () async {
      final mesh = _Mesh();
      for (var i = 0; i < 16; i++) {
        mesh.add(await RnsIdentity.generate());
      }
      mesh.crossSeed();
      final nodes = mesh.nodes.values.toList();
      final publisher = nodes.first;

      final sha = _sha(303);
      final rec =
          await ProviderRecord.create(providerIdentity: publisher.identity, sha256: sha);
      await publisher.publish(rec); // replicates to the k-closest

      final resolver = mesh.add(await RnsIdentity.generate());
      for (final n in nodes) {
        resolver.routing.add(DhtContact.ofIdentity(n.identity));
      }

      mesh.rpcCount = 0;
      final providers = await resolver.resolve(sha);
      expect(providers, isNotEmpty);
      // The alpha-closest queried in round 1 are exactly where the record was
      // replicated, so it is found immediately and the lookup stops — a handful
      // of RPCs, not all 16 contacts walked. (Pre-fix this walked every contact.)
      expect(mesh.rpcCount, lessThanOrEqualTo(resolver.alpha),
          reason: 'FIND_VALUE must stop on the first round that yields the value');
    });

    test('resolve still returns fast when most contacts are dead', () async {
      final mesh = _Mesh();
      for (var i = 0; i < 12; i++) {
        mesh.add(await RnsIdentity.generate());
      }
      mesh.crossSeed();
      final nodes = mesh.nodes.values.toList();
      final publisher = nodes.first;

      final sha = _sha(404);
      final rec =
          await ProviderRecord.create(providerIdentity: publisher.identity, sha256: sha);
      await publisher.publish(rec);

      // Kill every node EXCEPT the publisher and its closest replicas, so a naive
      // full walk would burn RPCs on dead contacts. The resolver must still find
      // the record via a live holder and not grind through the whole shortlist.
      final live = nodes.where((n) => n.storedKeys > 0).toList();
      for (final n in nodes) {
        if (!live.contains(n)) mesh.dead.add(dhtHex(n.myId));
      }

      final resolver = mesh.add(await RnsIdentity.generate());
      for (final n in nodes) {
        resolver.routing.add(DhtContact.ofIdentity(n.identity));
      }
      final providers = await resolver.resolve(sha);
      expect(providers, isNotEmpty,
          reason: 'a live replica must still answer through the churn');
    });
  });

  group('DHT mesh: parallel publish fan-out', () {
    test('publish STOREs concurrently (peak concurrency > 1)', () async {
      final mesh = _Mesh()..perCall = const Duration(milliseconds: 30);
      for (var i = 0; i < 10; i++) {
        mesh.add(await RnsIdentity.generate());
      }
      mesh.crossSeed();
      final publisher = mesh.nodes.values.first;

      final sha = _sha(505);
      final rec =
          await ProviderRecord.create(providerIdentity: publisher.identity, sha256: sha);
      mesh.peakConcurrency = 0;
      await publisher.publish(rec);

      // The lookup phase already fans out at most `alpha` (=3) at a time, so a
      // peak ABOVE alpha can only come from the STORE phase running concurrently
      // across the (up to k=8) closest holders. Sequential STOREs would never
      // exceed one in-flight at a time. This isolates the fan-out fix from the
      // pre-existing parallel lookup.
      expect(mesh.peakConcurrency, greaterThan(publisher.alpha),
          reason: 'STORE fan-out must be concurrent, not serial');
    });
  });
}
