/*
 * The All tab was empty for twenty minutes while four relays were connected.
 *
 * Not one bug — four, each hiding the next, and every one of them invisible from
 * the outside because the logs said `seen=201` and everything looked healthy:
 *
 *   1. relays replay their recent window on every REQ, and nothing deduped it —
 *      so the same posts were gated again and again;
 *   2. the flood rule counted DELIVERIES, so an honest author redelivered by four
 *      relays looked like a spammer and their real posts were rejected. Adding a
 *      relay made the feed emptier;
 *   3. that stale replay counted as "proof of life", so the watchdog could never
 *      escalate;
 *   4. a post whose author's kind-0 never arrived was held for three minutes and
 *      then DESTROYED, and the expiry sweep only ran when the next post was held —
 *      so when the firehose went quiet the queue froze forever.
 *
 * These tests are the four of them, pinned.
 */
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Store implements NostrStore {
  final Map<String, NostrEvent> byId = {};
  @override
  bool put(NostrEvent e, {int tier = 2}) {
    if (e.id == null || byId.containsKey(e.id)) return false;
    byId[e.id!] = e;
    return true;
  }

  @override
  List<NostrEvent> query(NostrFilter f) =>
      byId.values.where((e) => NostrWire.matches(f, e)).toList();
  @override
  bool addReaction(String eventId, String pubkey) => true;
  @override
  List<String> reactionPubkeys(String eventId) => const [];
  @override
  List<String> replyIdsFor(String eventId) => const [];
}

class _FakeClient implements NostrRelayClient {
  @override
  final String uri;
  _FakeClient(this.uri);
  @override
  NostrEventCallback? onEvent;
  @override
  NostrEoseCallback? onEose;
  @override
  NostrClosedCallback? onClosed;
  @override
  NostrStatusCallback? onStatus;
  final List<String> subscribed = [];
  final List<List<NostrFilter>> filters = [];
  int reconnects = 0;
  @override
  NostrRelayStatus status = NostrRelayStatus.connected;
  @override
  Future<void> connect() async {}
  @override
  void subscribe(String subId, List<NostrFilter> f) {
    subscribed.add(subId);
    filters.add(f);
  }

  @override
  int drainFrames() => 0;
  @override
  void resume() {}
  @override
  void disconnect() {}
  @override
  Future<void> reconnectFresh() async {}
  @override
  void reconnect() => reconnects++;
  @override
  void unsubscribe(String subId) {}
  @override
  Future<bool> publish(NostrEvent e) async => true;
  @override
  Future<void> close() async {}
  void inject(String subId, NostrEvent e) => onEvent?.call(subId, e);
}

NostrEvent _signed(
  NostrKeyPair kp, {
  int kind = 1,
  String content = 'a real post',
  int at = 1700000000,
}) {
  final e = NostrEvent(
    pubkey: kp.publicKeyHex,
    createdAt: at,
    kind: kind,
    tags: const [],
    content: content,
  );
  e.sign(kp.privateKeyHex);
  return e;
}

void main() {
  late Directory dir;
  late String persist;
  late _Store store;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('fire');
    persist = '${dir.path}/relays.json';
    store = _Store();
    File(persist).writeAsStringSync('[{"uri":"rns://${'a' * 64}"}]');
  });
  tearDown(() => dir.deleteSync(recursive: true));

  NostrRelayHub hub(_FakeClient fake) => NostrRelayHub(
    store: store,
    persistPath: persist,
    rnsClientFactory: (_) => fake,
    defaultRelays: const [],
  );

  test(
    'the SAME event redelivered is not news, and cannot flood its author out',
    () async {
      // One honest author, one post — handed to us eight times, as four relays and
      // two re-opens would. maxPerMinute is 4: counting deliveries, this author is
      // "flooding" and their post is rejected. Counting events, they posted once.
      final author = NostrCrypto.generateKeyPair();
      final fake = _FakeClient('rns://${'a' * 64}');
      final h = hub(fake);
      await h.init();

      final sub = h.subscribeFirehose(requireProfile: false);
      final relaySub = fake.subscribed.last;
      final post = _signed(author, content: 'the only thing I said today');

      for (var i = 0; i < 8; i++) {
        fake.inject(relaySub, post);
      }
      h.debugCurateNow(); // the curator holds candidates; flush it

      final got = h.drainEvents(sub, max: 20);
      expect(got, hasLength(1), reason: 'shown once');
      expect(got.single['content'], 'the only thing I said today');

      final stats = h.drainFirehoseStats();
      expect(stats['new'], 1, reason: 'one real event');
      expect(stats['dup'], 7, reason: 'seven redeliveries, named as such');
      expect(
        stats['flooding'] ?? 0,
        0,
        reason:
            'a redelivery must NEVER look like a flood — that is what made '
            'the feed emptier the more relays you added',
      );
      await h.close();
    },
  );

  test(
    'a redelivery is not proof of life — the watchdog can still escalate',
    () async {
      // The relay replays its cache and goes dead. The old code took that replay as
      // "the firehose is alive", reset the silence counter, and never cycled the
      // socket — for twenty minutes.
      final author = NostrCrypto.generateKeyPair();
      final fake = _FakeClient('rns://${'a' * 64}');
      final h = hub(fake);
      await h.init();

      h.subscribeFirehose(requireProfile: false);
      final relaySub = fake.subscribed.last;
      final post = _signed(author);
      fake.inject(relaySub, post); // genuinely new: proof of life, correctly
      final firstNew = h.drainFirehoseStats()['new'];
      expect(firstNew, 1);

      fake.inject(relaySub, post); // the replay
      fake.inject(relaySub, post);
      final s = h.drainFirehoseStats();
      expect(
        s['new'],
        0,
        reason: 'nothing new arrived, and the stats must say so plainly',
      );
      expect(s['dup'], 2);
      await h.close();
    },
  );

  test(
    'a post whose author has no profile is SHOWN when the hold expires',
    () async {
      // The strict gate held it waiting for a kind-0 that never came, then threw it
      // away. A name that never arrives must not cost the user the post.
      final stranger = NostrCrypto.generateKeyPair();
      final f = FirehoseFilter(
        requireProfile: true,
        pendingTtl: const Duration(milliseconds: 50),
      );
      final post = _signed(stranger, content: 'a stranger with no profile');

      final v = f.verdict(
        post,
        hasProfile: (_) => false,
        trusted: (_) => false,
        muted: (_) => false,
        nowMs: 1000,
      );
      expect(v, isA<FeedPending>());
      f.hold(post, 1000);
      expect(f.pendingNow, 1);

      // Nothing else arrives — the old code's expiry only ran when the NEXT post
      // was held, so the queue froze and the post was never seen again.
      final ripe = f.sweepExpired(1000 + 60);
      expect(ripe.map((e) => e.content), [
        'a stranger with no profile',
      ], reason: 'delivered, not destroyed');
      expect(f.pendingNow, 0, reason: 'the queue drains without new traffic');
    },
  );

  test('a FORGED event that passes the content gate is still refused', () async {
    // Verification moved from "every delivery" to "what we keep" — for speed.
    // The security property must survive the move: a good-looking post with a
    // bad signature gets past the cheap gate and must die at the verify.
    final fake = _FakeClient('rns://${'a' * 64}');
    final h = hub(fake);
    await h.init();

    final sub = h.subscribeFirehose(requireProfile: false);
    final relaySub = fake.subscribed.last;

    final honest = NostrCrypto.generateKeyPair();
    final forged = _signed(honest,
        content: 'a perfectly plausible sentence someone might write');
    // Corrupt the signature after signing: id stays right, Schnorr fails.
    final bad = NostrEvent.fromJson({
      ...forged.toJson(),
      'sig': ('0' * 128),
    });
    fake.inject(relaySub, bad);
    h.debugCurateNow();

    expect(h.drainEvents(sub), isEmpty,
        reason: 'forged events must never be delivered');
    expect(store.byId, isNot(contains(bad.id)),
        reason: 'forged events must never be stored');
    await h.close();
  });

  test('the kind-0 that releases held posts is never rate-shed', () async {
    // The profile answers arrive as a burst — 100 authors × every relay — which is
    // exactly the shape the generic rate cap throws away. It was shedding the very
    // events that unlock the pending queue.
    final stranger = NostrCrypto.generateKeyPair();
    final fake = _FakeClient('rns://${'a' * 64}');
    final h = hub(fake);
    await h.init();

    final sub = h.subscribeFirehose(); // strict: requireProfile on
    final relaySub = fake.subscribed.last;

    const held = 'held until you know me, with enough context to curate';
    fake.inject(relaySub, _signed(stranger, content: held));
    expect(h.drainEvents(sub), isEmpty, reason: 'held, waiting for a name');

    // A flood of other traffic on the generic path, then the profile.
    final other = h.subscribe([
      const NostrFilter(kinds: [1]),
    ]);
    for (var i = 0; i < 60; i++) {
      final k = NostrCrypto.generateKeyPair();
      fake.inject(other, _signed(k, content: 'noise $i', at: 1700000100 + i));
    }
    fake.inject(other, _signed(stranger, kind: 0, content: '{"name":"Alice"}'));
    h.debugCurateNow();

    expect(
      h.drainEvents(sub).map((e) => e['content']),
      [held],
      reason:
          'the profile arrived, so the post it was holding is released — '
          'even though the cap was saturated',
    );
    await h.close();
  });

  test(
    'a re-open asks for what is NEW (since), not the same 200 again',
    () async {
      final author = NostrCrypto.generateKeyPair();
      final fake = _FakeClient('rns://${'a' * 64}');
      final h = hub(fake);
      await h.init();

      h.subscribeFirehose(requireProfile: false);
      final firstFilter = fake.filters.last.single;
      final nowSec = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      expect(
        firstFilter.since,
        inInclusiveRange(nowSec - 601, nowSec - 599),
        reason: 'cold start must ask only for the current ten-minute edition',
      );

      fake.inject(fake.subscribed.last, _signed(author, at: nowSec));
      h.debugReopenFirehose(); // what the watchdog does

      final second = fake.filters.last.single;
      expect(
        second.since,
        isNotNull,
        reason:
            'a re-open must not drag the same backlog back across the '
            'network — that replay is what fed every other bug here',
      );
      expect(second.since, inInclusiveRange(nowSec - 60, nowSec));
      await h.close();
    },
  );
}
