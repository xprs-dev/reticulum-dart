/*
 * DHT-over-chat-dest routing — regression lock for running DHT RPC over a
 * configurable destination (the reliably-announced chat dest) instead of the
 * dedicated geogram/dht dest.
 *
 * On the public-hub mesh the geogram/dht announce is dropped by the hubs'
 * announce budget, so peers have NO transport path to each other's dht dest and
 * STOREs never land (replication failed; resolve only worked because the holder
 * kept its own record + k=96). Routing DHT RPC over the chat dest (whose announce
 * propagates reliably) fixes that. This test proves the ROUTING DEST is what
 * decides the outcome: with a transport path to ONLY the peer's chat dest, a
 * publish() with rpcAspects=['chat'] lands the STORE on the peer, while the
 * default ['dht'] (no path) does not.
 *
 * Unlike dht_mesh_test (which injects a direct sendRpc and bypasses dest routing
 * entirely), this drives the real RnsLink handshake through handlePacket, so it
 * actually exercises _dhtRpcRaw / _acceptDhtLink / dest dispatch.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// One side of a 2-node loopback: parses raw bytes back into packets and feeds
/// them to its node one at a time (mirrors how the real transport delivers).
class _Loop {
  late FileTransferNode node;
  final List<RnsPacket> _inbox = [];
  bool _pumping = false;

  void deliver(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    _inbox.add(p);
    _pump();
  }

  Future<void> _pump() async {
    if (_pumping) return;
    _pumping = true;
    while (_inbox.isNotEmpty) {
      final p = _inbox.removeAt(0);
      try {
        await node.handlePacket(p);
      } catch (_) {/* a wrong-peer packet is ignored, as on the wire */}
    }
    _pumping = false;
  }
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _sha32(int seed) =>
    Uint8List.fromList(List<int>.generate(32, (i) => (seed + i * 7) & 0xff));

void main() {
  group('DHT-over-chat-dest routing', () {
    /// Publisher A + holder B, wired loopback, where A has a transport path ONLY
    /// to B's chat dest (modelling hubs that dropped B's geogram/dht announce).
    /// [aAspects] is A's outbound DHT RPC dest aspects; B accepts on [bAspects].
    Future<(FileTransferNode a, FileTransferNode b)> pair(
        List<String> aAspects, List<String> bAspects) async {
      final aId = await RnsIdentity.generate();
      final bId = await RnsIdentity.generate();
      final bPub = RnsIdentity.fromPublicKey(bId.getPublicKey());
      final loopA = _Loop();
      final loopB = _Loop();
      // Only B's chat dest is routable; its dht dest is NOT (announce dropped).
      final bChatHex =
          _hex(RnsDestination.hash(bPub, 'geogram', ['chat']));

      loopA.node = FileTransferNode(
        identity: aId,
        source: const EmptyFileSource(),
        send: (raw) => loopB.deliver(raw),
        enableDht: true,
        rpcApp: 'geogram',
        rpcAspects: aAspects,
        hasPathForDest: (h) => _hex(h) == bChatHex,
        nextHopForDest: (h) => null, // direct neighbour over the loopback
        // requestPath omitted → ensurePath does no polling → fast fail for dht.
      );
      loopB.node = FileTransferNode(
        identity: bId,
        source: const EmptyFileSource(),
        send: (raw) => loopA.deliver(raw),
        enableDht: true,
        rpcApp: 'geogram',
        rpcAspects: bAspects,
      );
      // A knows B as a DHT contact (Kademlia id derived from B's identity).
      loopA.node.dht!.routing.add(DhtContact.ofIdentity(bPub));
      return (loopA.node, loopB.node);
    }

    test('rpcAspects=[chat]: STORE lands on the peer (chat path exists)',
        () async {
      final (a, b) = await pair(['chat'], ['chat']);
      final rec = await ProviderRecord.create(
          providerIdentity: a.identity, sha256: _sha32(11));
      final holders = await a.dht!.publish(rec);

      expect(b.dht!.storedKeys, greaterThan(0),
          reason: 'STORE must reach the peer when RPC rides the routable chat dest');
      expect(holders, greaterThanOrEqualTo(1));
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('default rpcAspects=[dht]: cannot reach the peer (no dht path)',
        () async {
      // Same chat-only path availability, but A dials the dht dest (default) to
      // which there is no path → skip → the STORE never reaches B.
      final (a, b) = await pair(['dht'], ['chat']);
      await a.dht!.publish(await ProviderRecord.create(
          providerIdentity: a.identity, sha256: _sha32(22)));

      expect(b.dht!.storedKeys, 0,
          reason: 'with no path to the dht dest the STORE must not reach the peer');
    }, timeout: const Timeout(Duration(seconds: 30)));
  });
}
