/*
 * NOSTR relay wire codec + filter matcher — the transport-agnostic protocol
 * surface. No sockets: encode/decode the NIP-01 JSON frames and match filters.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

NostrEvent _signed(NostrKeyPair kp,
    {int kind = 1, String content = 'hi', List<List<String>> tags = const []}) {
  final e = NostrEvent(
    pubkey: kp.publicKeyHex,
    createdAt: 1700000000,
    kind: kind,
    tags: tags,
    content: content,
  );
  e.sign(kp.privateKeyHex);
  return e;
}

void main() {
  final kp = NostrCrypto.generateKeyPair();

  group('NostrWire encode/decode', () {
    test('REQ round-trips through decode as a server ingest', () {
      final frame = NostrWire.req('sub1', [
        const NostrFilter(kinds: [1], authors: ['abc'], limit: 20)
      ]);
      final m = NostrWire.decode(frame);
      expect(m, isA<NostrReqMsg>());
      final r = m as NostrReqMsg;
      expect(r.subId, 'sub1');
      expect(r.filters.single.kinds, [1]);
      expect(r.filters.single.authors, ['abc']);
    });

    test('client EVENT (publish) decodes to NostrPublishMsg', () {
      final e = _signed(kp);
      final m = NostrWire.decode(NostrWire.event(e));
      expect(m, isA<NostrPublishMsg>());
      expect((m as NostrPublishMsg).event.id, e.id);
      expect(m.event.verify(), true);
    });

    test('relay EVENT (with subId) decodes to NostrEventMsg', () {
      final e = _signed(kp);
      final m = NostrWire.decode(NostrWire.eventFor('s', e));
      expect(m, isA<NostrEventMsg>());
      expect((m as NostrEventMsg).subId, 's');
      expect(m.event.id, e.id);
    });

    test('EOSE / OK / NOTICE / CLOSED / CLOSE decode', () {
      expect((NostrWire.decode(NostrWire.eose('s')) as NostrEoseMsg).subId, 's');
      final ok = NostrWire.decode(NostrWire.ok('id1', true, 'ok')) as NostrOkMsg;
      expect(ok.accepted, true);
      expect(ok.eventId, 'id1');
      expect((NostrWire.decode(NostrWire.notice('hi')) as NostrNoticeMsg).message,
          'hi');
      expect((NostrWire.decode(NostrWire.closed('s', 'bye')) as NostrClosedMsg)
          .message, 'bye');
      expect((NostrWire.decode(NostrWire.close('s')) as NostrCloseMsg).subId, 's');
    });

    test('malformed frames decode to null, never throw', () {
      for (final f in ['', 'not json', '{}', '[]', '["WAT"]', '["EVENT"]']) {
        expect(NostrWire.decode(f), isNull, reason: f);
      }
    });
  });

  group('NostrWire.matches (NIP-01 filter)', () {
    test('kinds + authors + since/until + tags', () {
      final e = _signed(kp, kind: 1, tags: [
        ['t', 'nostr'],
        ['p', 'xyz']
      ]);
      expect(NostrWire.matches(const NostrFilter(kinds: [1]), e), true);
      expect(NostrWire.matches(const NostrFilter(kinds: [0]), e), false);
      expect(
          NostrWire.matches(NostrFilter(authors: [kp.publicKeyHex]), e), true);
      expect(NostrWire.matches(const NostrFilter(authors: ['nope']), e), false);
      expect(NostrWire.matches(const NostrFilter(since: 1800000000), e), false);
      expect(NostrWire.matches(const NostrFilter(until: 1600000000), e), false);
      expect(
          NostrWire.matches(
              NostrFilter(tags: {
                't': ['nostr']
              }),
              e),
          true);
      expect(
          NostrWire.matches(
              NostrFilter(tags: {
                't': ['other']
              }),
              e),
          false);
    });
  });
}
