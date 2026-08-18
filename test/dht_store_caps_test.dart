/*
 * Anti-abuse store caps — bounds on the local provider-record store so a peer
 * that opens a DHT link (now possible over the widely-known chat dest) can't make
 * us hold unbounded records or burn CPU verifying a flood. A STORE over either
 * cap is refused BEFORE the signature verify; a refresh of a record we already
 * hold is always allowed (it doesn't grow the store).
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

Uint8List _sha(int seed) =>
    Uint8List.fromList(List<int>.generate(32, (i) => (seed * 131 + i) & 0xff));

void main() {
  group('DhtNode store caps (anti-abuse)', () {
    test('per-key provider cap rejects extra providers, allows refresh',
        () async {
      final me = await RnsIdentity.generate();
      final node = DhtNode(
        identity: me,
        sendRpc: (_, __) async => null,
        maxRecordsPerKey: 3,
        maxStoredKeys: 100,
      );
      final sha = _sha(1);

      final providers =
          await Future.wait(List.generate(3, (_) => RnsIdentity.generate()));
      for (final p in providers) {
        final resp = await node.handle(DhtMessage.store(p.getPublicKey(),
            await ProviderRecord.create(providerIdentity: p, sha256: sha)));
        expect(resp.ok, isTrue);
      }
      expect(node.storesRejected, 0);

      // A 4th DISTINCT provider for the same key is over the cap.
      final extra = await RnsIdentity.generate();
      final rej = await node.handle(DhtMessage.store(extra.getPublicKey(),
          await ProviderRecord.create(providerIdentity: extra, sha256: sha)));
      expect(rej.ok, isFalse);
      expect(node.storesRejected, 1);

      // A refresh of an already-held (key, provider) is always allowed.
      final refresh = await node.handle(DhtMessage.store(
          providers.first.getPublicKey(),
          await ProviderRecord.create(
              providerIdentity: providers.first, sha256: sha)));
      expect(refresh.ok, isTrue);
      expect(node.storesRejected, 1);
    });

    test('total key cap rejects new keys but not new providers for known keys',
        () async {
      final me = await RnsIdentity.generate();
      final node = DhtNode(
        identity: me,
        sendRpc: (_, __) async => null,
        maxStoredKeys: 2,
        maxRecordsPerKey: 100,
      );

      Future<bool> store(int keySeed) async {
        final p = await RnsIdentity.generate();
        final resp = await node.handle(DhtMessage.store(p.getPublicKey(),
            await ProviderRecord.create(
                providerIdentity: p, sha256: _sha(keySeed))));
        return resp.ok;
      }

      expect(await store(10), isTrue); // key A
      expect(await store(20), isTrue); // key B
      expect(node.storedKeys, 2);

      expect(await store(30), isFalse, reason: 'a 3rd distinct key is over cap');
      expect(node.storesRejected, 1);

      // A new provider for an EXISTING key is still admitted (no new key).
      expect(await store(10), isTrue);
      expect(node.storesRejected, 1);
    });
  });
}
