import 'package:reticulum/reticulum.dart';
import 'package:test/test.dart';

void main() {
  group('NOSTR identity & notes', () {
    test('keypair → npub round-trips and sign/verify works', () {
      final kp = NostrCrypto.generateKeyPair();
      expect(kp.npub, startsWith('npub1'));
      expect(NostrCrypto.decodeNpub(kp.npub).toLowerCase(),
          kp.publicKeyHex.toLowerCase());

      final ev = NostrEvent(
        pubkey: kp.publicKeyHex,
        createdAt: 1700000000,
        kind: NostrEventKind.textNote,
        tags: const [
          ['t', 'FEED']
        ],
        content: 'hello reticulum',
      );
      ev.sign(kp.privateKeyHex);
      expect(ev.id, isNotNull);
      expect(ev.sig, isNotNull);
      expect(ev.verify(), isTrue);

      // Tamper → verification fails.
      final forged = NostrEvent.fromJson(ev.toJson()..['content'] = 'tampered');
      expect(forged.verify(), isFalse);
    });
  });

  group('Reticulum identity', () {
    test('generates a 16-byte addressable identity', () async {
      final id = await RnsIdentity.generate();
      expect(id.hash.length, 16);
      expect(id.hexHash.length, 32);
      final other = await RnsIdentity.generate();
      expect(id.hexHash, isNot(other.hexHash));
    });
  });
}
