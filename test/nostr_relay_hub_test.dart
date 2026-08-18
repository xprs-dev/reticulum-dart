/*
 * NostrRelayHub — the transport-abstract orchestrator: relay list add/remove/
 * persist, subscribe fanning to every transport, inbound events merging into the
 * ONE store and buffering per-sub for the wapp to drain, publish fanning out.
 * A fake client stands in for the network transports so no sockets are opened.
 */
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// In-memory store so the hub is testable without the sqlite native library.
class _FakeStore implements NostrStore {
  final Map<String, NostrEvent> byId = {};
  final Map<String, Set<String>> reactions = {};
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
  bool addReaction(String eventId, String pubkey) =>
      reactions.putIfAbsent(eventId, () => <String>{}).add(pubkey);

  @override
  List<String> reactionPubkeys(String eventId) =>
      reactions[eventId]?.toList() ?? const [];

  @override
  List<String> replyIdsFor(String eventId) => [
    for (final e in byId.values)
      if (e.kind == 1 &&
          e.tags.any((t) => t.length >= 2 && t[0] == 'e' && t[1] == eventId))
        e.id!,
  ];
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
  final List<NostrEvent> published = [];
  @override
  NostrRelayStatus status = NostrRelayStatus.connected;

  @override
  Future<void> connect() async {}
  @override
  void subscribe(String subId, List<NostrFilter> filters) =>
      subscribed.add(subId);
  @override
  int drainFrames() => 0;
  @override
  void resume() {}
  @override
  void disconnect() {}
  @override
  Future<void> reconnectFresh() async {}
  @override
  void reconnect() {}

  @override
  void unsubscribe(String subId) {}
  @override
  Future<bool> publish(NostrEvent event) async {
    published.add(event);
    return true;
  }

  @override
  Future<void> close() async {}

  /// Simulate a relay pushing an event to this client's subscription.
  void inject(String subId, NostrEvent e) => onEvent?.call(subId, e);
}

NostrEvent _signed(
  NostrKeyPair kp, {
  int kind = 1,
  String content = 'hi',
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
  late _FakeStore store;
  final kp = NostrCrypto.generateKeyPair();

  setUp(() {
    dir = Directory.systemTemp.createTempSync('nostrhub');
    persist = '${dir.path}/relays.json';
    store = _FakeStore();
    // Seed the list with local + one rns relay so init() does NOT pull the
    // wss:// defaults (which would open real sockets).
    File(
      persist,
    ).writeAsStringSync('[{"uri":"local"},{"uri":"rns://${'a' * 64}"}]');
  });

  tearDown(() {
    dir.deleteSync(recursive: true);
  });

  // No public defaults: these tests must never open a real socket.
  NostrRelayHub makeHub(_FakeClient fake, {void Function(NostrEvent)? onStored}) =>
      NostrRelayHub(
        store: store,
        persistPath: persist,
        rnsClientFactory: (uri) => fake,
        onStored: onStored,
        defaultRelays: const [],
      );

  test('init loads persisted relays + builds a client per endpoint', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = makeHub(fake);
    await hub.init();
    final list = hub.relaysJson();
    expect(list.map((e) => e['uri']), containsAll(['local', fake.uri]));
    expect(list.firstWhere((e) => e['uri'] == fake.uri)['scheme'], 'reticulum');
    expect(list.firstWhere((e) => e['uri'] == 'local')['scheme'], 'local');
    await hub.close();
  });

  test(
    'subscribe answers from local store AND fans to the rns transport',
    () async {
      final backlog = _signed(kp, content: 'stored', at: 1700000001);
      store.put(backlog);
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = makeHub(fake);
      await hub.init();

      final sub = hub.subscribe([
        NostrFilter(authors: [kp.publicKeyHex]),
      ]);
      // Local backlog reached the wapp inbox synchronously.
      final drained = hub.drainEvents(sub);
      expect(drained.map((e) => e['content']), contains('stored'));
      // The rns transport got the same subscription.
      expect(fake.subscribed, contains(sub));
      await hub.close();
    },
  );

  test(
    'an inbound event merges into the store and buffers once per sub',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final stored = <NostrEvent>[];
      final hub = makeHub(fake, onStored: stored.add);
      await hub.init();
      final sub = hub.subscribe([
        const NostrFilter(kinds: [1]),
      ]);
      hub.drainEvents(sub); // clear any local backlog

      final e = _signed(kp, content: 'live', at: 1700000002);
      fake.inject(sub, e);
      fake.inject(sub, e); // duplicate from another relay → delivered once

      expect(store.query(NostrFilter(ids: [e.id!])).length, 1);
      expect(stored.where((s) => s.id == e.id).length, 1);
      final drained = hub.drainEvents(sub);
      expect(drained.length, 1);
      expect(drained.single['content'], 'live');
      await hub.close();
    },
  );

  test('publish writes to the store and fans to the transport', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = makeHub(fake);
    await hub.init();
    final e = _signed(kp, content: 'mine', at: 1700000003);
    await hub.publish(e);
    expect(store.query(NostrFilter(ids: [e.id!])).length, 1);
    expect(fake.published.single.id, e.id);
    await hub.close();
  });

  test('addRelay validates scheme + persists; removeRelay drops it', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = makeHub(fake);
    await hub.init();

    expect(hub.addRelay('wss://relay.example.com'), true);
    expect(hub.addRelay('wss://relay.example.com'), false); // dup
    expect(hub.addRelay('gopher://nope'), false); // unknown scheme
    expect(File(persist).readAsStringSync(), contains('relay.example.com'));

    expect(hub.removeRelay('wss://relay.example.com'), true);
    expect(
      File(persist).readAsStringSync(),
      isNot(contains('relay.example.com')),
    );
    await hub.close();
  });

  // ── The live firehose (the "All" tab) ─────────────────────────────────────

  test(
    'the firehose delivers a fresh post immediately — no likes required',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = makeHub(fake);
      await hub.init();

      final sub = hub.subscribeFirehose(requireProfile: false);
      final relaySub = fake.subscribed.last;

      fake.inject(
        relaySub,
        _signed(kp, content: 'a post nobody has liked yet'),
      );
      hub.debugCurateNow(); // strangers are ranked, then handed over

      expect(
        hub.drainEvents(sub).map((e) => e['content']),
        ['a post nobody has liked yet'],
        reason:
            'this is the whole point: discovery can only show posts old '
            'enough to have gathered likes, so it can never be the All tab',
      );
      await hub.close();
    },
  );

  test(
    'manual refresh completes with one generation-tagged append batch',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = NostrRelayHub(
        store: store,
        persistPath: persist,
        defaultRelays: const [],
        rnsClientFactory: (_) => fake,
        firehoseOpeningDelay: const Duration(days: 1),
        firehoseSettleDelay: Duration.zero,
      );
      await hub.init();

      final sub = hub.subscribeFirehose(requireProfile: false);
      final relaySub = fake.subscribed.last;
      for (var i = 0; i < 3; i++) {
        final author = NostrCrypto.generateKeyPair();
        fake.inject(
          relaySub,
          _signed(
            author,
            content: 'manual refresh candidate number $i has useful context',
            at: 1700000100 + i,
          ),
        );
      }

      expect(await hub.refreshBurst(n: 100), 3);
      final batch = hub.drainEvents(sub, max: 100);
      expect(batch, hasLength(3));
      expect(batch.map((e) => e['_xprs_batch_mode']).toSet(), {'manual'});
      expect(batch.map((e) => e['_xprs_batch']).toSet(), hasLength(1));
      expect(batch.map((e) => e['_xprs_batch_size']).toSet(), {3});
      expect(batch.map((e) => e['_xprs_batch_index']), [0, 1, 2]);
      await hub.close();
    },
  );

  test('automatic edition never bypasses the strict curator', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = NostrRelayHub(
      store: store,
      persistPath: persist,
      defaultRelays: const [],
      rnsClientFactory: (_) => fake,
      firehoseOpeningDelay: const Duration(days: 1),
      firehoseSettleDelay: Duration.zero,
    );
    await hub.init();

    final sub = hub.subscribeFirehose(requireProfile: false);
    fake.inject(
      fake.subscribed.last,
      _signed(
        kp,
        content: 'Useful context with an unengaged link https://example.com',
        at: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      ),
    );

    expect(await hub.resumeAndRefreshFirehose(), 0);
    expect(hub.drainEvents(sub), isEmpty);
    await hub.close();
  });

  test(
    'automatic deadline ignores overlap and survives an empty batch',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = NostrRelayHub(
        store: store,
        persistPath: persist,
        defaultRelays: const [],
        rnsClientFactory: (_) => fake,
        pollInterval: const Duration(milliseconds: 100),
        firehoseOpeningDelay: const Duration(days: 1),
        firehoseSettleDelay: const Duration(milliseconds: 30),
        firehoseConnectGrace: Duration.zero,
      );
      await hub.init();
      hub.subscribeFirehose(requireProfile: false);

      final initialRequests = fake.subscribed.length;
      final firstDeadline = DateTime.now().millisecondsSinceEpoch + 1000;
      hub.backgroundTick(nowMs: firstDeadline);
      hub.backgroundTick(nowMs: firstDeadline); // overlap: ignored, in flight
      // The edition reconnects the sockets fresh before it REQs (off-grid: never
      // trust an existing socket), so the REQ lands a microtask later.
      await Future<void>.delayed(const Duration(milliseconds: 5));
      expect(fake.subscribed.length, initialRequests + 1);

      await Future<void>.delayed(const Duration(milliseconds: 50));
      hub.backgroundTick(nowMs: firstDeadline + 101);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      expect(fake.subscribed.length, initialRequests + 2);
      await hub.close();
    },
  );

  test(
    'tab-toggle churn cannot push the automatic deadline out of reach',
    () async {
      // Every All -> Following -> All toggle tears the firehose down and brings
      // a new "first subscriber". Re-arming the deadline on each one meant a
      // user merely USING the app kept the first automatic edition permanently
      // ten minutes away. The schedule belongs to the wall clock: a re-subscribe
      // inherits the pending deadline, and a due tick after churn still fires.
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = NostrRelayHub(
        store: store,
        persistPath: persist,
        defaultRelays: const [],
        rnsClientFactory: (_) => fake,
        pollInterval: const Duration(milliseconds: 100),
        firehoseOpeningDelay: const Duration(days: 1),
        firehoseSettleDelay: const Duration(milliseconds: 10),
        firehoseConnectGrace: Duration.zero,
      );
      await hub.init();

      final first = hub.subscribeFirehose(requireProfile: false);
      final due = DateTime.now().millisecondsSinceEpoch + 150;

      // Churn: close the tab, reopen it. Twice, for good measure.
      hub.unsubscribe(first);
      final second = hub.subscribeFirehose(requireProfile: false);
      hub.unsubscribe(second);
      hub.subscribeFirehose(requireProfile: false);

      final before = fake.subscribed.length;
      hub.backgroundTick(nowMs: due);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      expect(
        fake.subscribed.length,
        before + 1,
        reason: 'the deadline armed by the FIRST subscribe must still be '
            'honoured — churn used to reset it to now+10min every time',
      );
      await hub.close();
    },
  );

  test('a relay burst bigger than the rate cap still reaches the feed', () async {
    // A relay answers a fresh kind-1 subscription with its recent window in one
    // go — hundreds of events, instantly, from every relay at once. The generic
    // rate cap (15 per 250ms) used to run FIRST and threw that burst away before
    // the quality gate saw a single post: four live relays, and an All tab that
    // had not moved in sixteen hours.
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = makeHub(fake);
    await hub.init();

    final sub = hub.subscribeFirehose(requireProfile: false);
    final relaySub = fake.subscribed.last;

    // Distinct authors — a relay's burst is the whole network talking, and the
    // gate (rightly) throttles ONE author shouting.
    const burst = 40; // >> the 15-per-window cap
    for (var i = 0; i < burst; i++) {
      final author = NostrCrypto.generateKeyPair();
      fake.inject(
        relaySub,
        _signed(
          author,
          content: 'relay burst post number $i has useful context',
          at: 1700000000 + i,
        ),
      );
    }

    // The curator hands the feed a handful at a time — flush until it is empty.
    for (var i = 0; i < 30; i++) {
      if (hub.debugCurateNow() == 0) break;
    }
    expect(
      hub.drainEvents(sub, max: burst * 2),
      hasLength(burst),
      reason:
          'the gate decides what the feed shows, not a cap sized for '
          'sqlite writes on a thread the hub no longer runs on',
    );
    await hub.close();
  });

  test(
    'a muted author is refused by the gate — by the 12-char key the feed shows',
    () async {
      // The user mutes what they can see, and what they can see on a post is the
      // first 12 hex chars of the author's key. The host keys it upper-case; the
      // wire is lower-case. Both must hit.
      final spammer = NostrCrypto.generateKeyPair();
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = makeHub(fake);
      await hub.init();
      hub.mutedAuthors = {spammer.publicKeyHex.substring(0, 12).toUpperCase()};

      final sub = hub.subscribeFirehose(requireProfile: false);
      final relaySub = fake.subscribed.last;

      fake.inject(relaySub, _signed(spammer, content: 'buy my coin, scumbag'));
      const kept = 'a real post with enough detail to curate';
      fake.inject(relaySub, _signed(kp, content: kept));
      hub.debugCurateNow();

      expect(
        hub.drainEvents(sub).map((e) => e['content']),
        [kept],
        reason:
            'a mute is a refusal to CARRY, not a place to hide a post '
            'we stored anyway',
      );
      expect(
        store.query(NostrFilter(authors: [spammer.publicKeyHex])),
        isEmpty,
        reason: 'the muted post must never reach the store',
      );
      await hub.close();
    },
  );

  test('the firehose drops spam before it is ever stored', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = makeHub(fake);
    await hub.init();

    final sub = hub.subscribeFirehose(requireProfile: false);
    final relaySub = fake.subscribed.last;

    fake.inject(
      relaySub,
      _signed(
        kp,
        content: 'https://spam.example/a https://spam.example/b',
        at: 1700000002,
      ),
    );

    expect(hub.drainEvents(sub), isEmpty);
    expect(
      store.byId.values.any((e) => e.content.startsWith('https://spam')),
      isFalse,
      reason: 'a public firehose must not write junk into sqlite all day',
    );
    await hub.close();
  });

  test(
    'a post from an unknown author waits for their profile, then appears',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = makeHub(fake);
      await hub.init();

      // Strict: the author must have a kind-0 we have seen.
      final sub = hub.subscribeFirehose();
      final relaySub = fake.subscribed.last;

      final author = NostrCrypto.generateKeyPair();
      fake.inject(
        relaySub,
        _signed(
          author,
          content: 'hello, I am new here and learning how this works',
          at: 1700000003,
        ),
      );

      expect(
        hub.drainEvents(sub),
        isEmpty,
        reason: 'held, pending their profile',
      );

      // Their kind-0 arrives on the same subscription (which is why the firehose
      // asks for kind-0 alongside kind-1).
      fake.inject(
        relaySub,
        _signed(author, kind: 0, content: '{"name":"newbie"}', at: 1700000004),
      );
      hub.debugCurateNow();

      expect(
        hub.drainEvents(sub).map((e) => e['content']),
        contains('hello, I am new here and learning how this works'),
        reason: 'a new account is not a spammer — their profile was in flight',
      );
      await hub.close();
    },
  );

  // ── The two discovery bugs ────────────────────────────────────────────────

  test('TWO discovery subscribers both get the feed', () async {
    final fake = _FakeClient('rns://${'a' * 64}');
    final hub = makeHub(fake);
    await hub.init();

    // The launcher hero subscribes first, the Social wapp second. The second
    // used to be handed the first one's id, with no inbox behind it — so it
    // drained nothing, forever.
    final hero = hub.subscribeDiscovery(minLikes: 1);
    final wapp = hub.subscribeDiscovery(minLikes: 1);
    expect(hero, isNot(wapp));

    final reactSub = fake.subscribed[fake.subscribed.length - 1];
    final post = _signed(kp, content: 'a popular post', at: 1700000005);

    // One like qualifies it, then the post itself arrives by id.
    final liker = NostrCrypto.generateKeyPair();
    final like = NostrEvent(
      pubkey: liker.publicKeyHex,
      createdAt: 1700000006,
      kind: 7,
      tags: [
        ['e', post.id!],
      ],
      content: '+',
    )..sign(liker.privateKeyHex);
    fake.inject(reactSub, like);
    fake.inject('anySub', post);

    expect(hub.drainEvents(hero).map((e) => e['content']), ['a popular post']);
    expect(
      hub.drainEvents(wapp).map((e) => e['content']),
      ['a popular post'],
      reason: 'whoever subscribed SECOND must not get a dead id',
    );
    await hub.close();
  });

  test(
    'unsubscribe then re-subscribe still delivers (pull-to-refresh)',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = makeHub(fake);
      await hub.init();

      final first = hub.subscribeDiscovery(minLikes: 1);
      hub.unsubscribe(first); // what pull-to-refresh does

      final second = hub.subscribeDiscovery(minLikes: 1);
      final reactSub = fake.subscribed.last;

      final post = _signed(kp, content: 'after the refresh', at: 1700000007);
      final liker = NostrCrypto.generateKeyPair();
      final like = NostrEvent(
        pubkey: liker.publicKeyHex,
        createdAt: 1700000008,
        kind: 7,
        tags: [
          ['e', post.id!],
        ],
        content: '+',
      )..sign(liker.privateKeyHex);
      fake.inject(reactSub, like);
      fake.inject('anySub', post);

      expect(
        hub.drainEvents(second).map((e) => e['content']),
        ['after the refresh'],
        reason:
            'unsubscribe left _discoFeedSub pointing at the deleted inbox, '
            'so refreshing the feed killed it for the life of the process',
      );
      await hub.close();
    },
  );

  test(
    'a torn-down firehose subId self-heals on drain (the frozen All feed)',
    () async {
      final fake = _FakeClient('rns://${'a' * 64}');
      final hub = makeHub(fake);
      await hub.init();

      // The wapp acquires a firehose subId once and caches it forever.
      final sub = hub.subscribeFirehose(requireProfile: false);

      // The hub tears the firehose down (Social closed): the id is dropped from
      // _fireSubscribers and its inbox deleted. The wapp does NOT know — it still
      // holds the id and keeps draining it every tick.
      hub.unsubscribe(sub);
      expect(
        hub.drainEvents(sub),
        isEmpty,
        reason: 'draining a torn-down id resurrects it, but has nothing yet',
      );

      // A fresh edition arrives after the wapp resumed draining. Before the fix
      // this went into a deleted inbox and the All feed stayed frozen forever;
      // now the drain above re-registered the id, so the post reaches it.
      final relaySub = fake.subscribed.last;
      fake.inject(relaySub, _signed(kp, content: 'post after self-heal'));
      hub.debugCurateNow();

      expect(
        hub.drainEvents(sub).map((e) => e['content']),
        ['post after self-heal'],
        reason:
            'the wapp only re-subscribes when its cached id is empty, so a '
            'torn-down firehose id MUST resurrect on drain — otherwise the All '
            'feed freezes while the Hero (which re-acquires each cycle) stays fresh',
      );
      await hub.close();
    },
  );
}
