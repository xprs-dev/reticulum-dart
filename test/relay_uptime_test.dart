/*
 * Locks the warm-start wire/contracts added for fast cold-start discovery:
 *   - the relay announcement carries a LIVE uptime that round-trips on the wire,
 *     so peers can rank stable nodes (likely indexers) first;
 *   - FileTransferNode.seedPeers warm-loads the DHT routing table from cached
 *     public keys (the persisted observed-node cache feeds this on boot).
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  group('relay announcement uptime', () {
    test('round-trips uptime on the wire', () {
      const ann = RelayAnnouncement(
          role: RelayRole.indexer, capacity: kCapUnknown, caps: RelayCap.search);
      final decoded = RelayAnnouncement.decode(ann.encode(uptimeSeconds: 7200));
      expect(decoded, isNotNull);
      expect(decoded!.uptimeSeconds, 7200);
      expect(decoded.role, RelayRole.indexer);
    });

    test('omits uptime when not advertised (0)', () {
      const ann = RelayAnnouncement(
          role: RelayRole.leaf, capacity: kCapUnknown, caps: 0);
      final decoded = RelayAnnouncement.decode(ann.encode());
      expect(decoded!.uptimeSeconds, 0);
    });

    test('RelayRoleManager stamps the live uptime on each announce', () {
      var fakeUptime = 10;
      final mgr = RelayRoleManager(uptimeProvider: () => fakeUptime);
      final first = RelayAnnouncement.decode(mgr.announcementAppData());
      expect(first!.uptimeSeconds, 10);
      fakeUptime = 999; // time passes
      final second = RelayAnnouncement.decode(mgr.announcementAppData());
      expect(second!.uptimeSeconds, 999);
    });
  });

  group('FileTransferNode.seedPeers (warm-start)', () {
    test('seeds the DHT routing table from cached public keys', () async {
      final me = await RnsIdentity.generate();
      final node = FileTransferNode(
        identity: me,
        source: const EmptyFileSource(),
        send: (_) {},
        enableDht: true,
      );
      expect(node.dhtRoutingSize, 0);
      final peers = [
        for (var i = 0; i < 3; i++) (await RnsIdentity.generate()).getPublicKey()
      ];
      final added = node.seedPeers(peers);
      expect(added, 3);
      expect(node.dhtRoutingSize, 3);
      // A malformed (wrong-length) key is skipped, not counted.
      expect(node.seedPeers([Uint8List(10)]), 0);
    });

    test('is a no-op without DHT enabled', () async {
      final me = await RnsIdentity.generate();
      final node = FileTransferNode(
          identity: me, source: const EmptyFileSource(), send: (_) {});
      final peers = [(await RnsIdentity.generate()).getPublicKey()];
      expect(node.seedPeers(peers), 0);
    });
  });
}
