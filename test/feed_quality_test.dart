/*
 * The gate that decides what a public firehose may show a user.
 *
 * The half of this that matters is the FALSE POSITIVES. A spam post that slips
 * through costs the user a moment's annoyance and they can see it happened. A
 * real person's post that is wrongly hidden is invisible to them, unfixable by
 * them, and indistinguishable from "the network is quiet" — so the "keeps" here
 * are the load-bearing tests, not the "drops".
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// 64-hex pubkeys, as the wire uses.
String _pk(String seed) => seed * 64;
final _alice = _pk('a');
final _bob = _pk('b');
final _stranger = _pk('z');
final _me = _pk('f');
final _friend = _pk('e');

NostrEvent _post(String content, {String? pubkey, int? at}) => NostrEvent(
  id: content.hashCode.toRadixString(16).padLeft(64, '0'),
  pubkey: pubkey ?? _alice,
  createdAt: at ?? 1752300000,
  kind: 1,
  tags: const [],
  content: content,
);

void main() {
  group('content rules keep what real people write', () {
    final keeps = <String, String>{
      'a short reply': 'yes, exactly this',
      'two characters': 'ok',
      'a link WITH a sentence':
          'this explains the routing bug better than I could https://example.org/x',
      'a couple of hashtags under real prose':
          'Spent the weekend getting the mesh to survive a hub outage. '
          'Notes and numbers in the post. #nostr #meshtastic',
      'Japanese': 'おはようございます。今日はいい天気ですね。',
      'Arabic': 'صباح الخير، كيف حالك اليوم؟',
      'Portuguese with an emoji': 'temos um beta release! 😂 finalmente',
      'a single emoji reply is short but human': 'haha 😂',
      'ALL CAPS is rude, not spam': 'HELLO DIVAS, HOW ARE WE TODAY?',
    };

    for (final e in keeps.entries) {
      test('keeps ${e.key}', () {
        expect(
          contentVerdict(e.value),
          isA<FeedKeep>(),
          reason: 'wrongly hidden: "${e.value}"',
        );
      });
    }
  });

  group('content rules drop the obvious', () {
    test('empty', () {
      expect(contentVerdict('   '), isA<FeedReject>());
      expect((contentVerdict('') as FeedReject).reason, FeedDrop.empty);
    });

    test('a wall of hashtags with a few words wedged in', () {
      final v = contentVerdict(
        'buy now #crypto #bitcoin #nostr #airdrop #free #money #pump #moon',
      );
      expect((v as FeedReject).reason, FeedDrop.hashtagStuffing);
    });

    test('a short promotional caption cannot hide behind three hashtags', () {
      final v = contentVerdict(
        'Jojo #npub1sexy 🍒 #NSFW #FitLifeAndBeyond 🏋️ 🌟',
      );
      expect((v as FeedReject).reason, FeedDrop.hashtagStuffing);
    });

    test('a post that is nothing but links', () {
      final v = contentVerdict('https://spam.example/a https://spam.example/b');
      expect((v as FeedReject).reason, FeedDrop.linkOnly);
    });

    test('an emoji wall', () {
      final v = contentVerdict('🚀🚀🚀💰💰💰🔥🔥🔥🎉🎉🎉');
      expect((v as FeedReject).reason, FeedDrop.symbolDominant);
    });
  });

  group('the stateful gate', () {
    late FirehoseFilter f;
    final known = <String>{_alice, _bob};

    FeedVerdict run(NostrEvent e, {int nowMs = 0}) => f.verdict(
      e,
      hasProfile: known.contains,
      trusted: (p) => p == _me || p == _friend,
      muted: (_) => false,
      nowMs: nowMs,
    );

    setUp(() => f = FirehoseFilter());

    test('a stranger with a profile and something to say gets through', () {
      expect(
        run(_post('the link budget runs out before the radio does')),
        isA<FeedKeep>(),
      );
    });

    test('an author with NO profile is held, not dropped', () {
      final v = run(_post('hello from a new account', pubkey: _stranger));
      expect(
        v,
        isA<FeedPending>(),
        reason:
            'a new user without a kind-0 is not a spammer — their profile '
            'may simply still be in flight',
      );
    });

    test('holding, then releasing when the profile lands', () {
      final e = _post('first post', pubkey: _stranger);
      expect(run(e), isA<FeedPending>());
      f.hold(e, 1000);

      final released = f.release(_stranger, 2000);
      expect(released.map((x) => x.content), ['first post']);
    });

    test('a held post whose profile never comes expires quietly', () {
      final e = _post('orphan', pubkey: _stranger);
      f.hold(e, 0);
      // 61s later the profile still has not arrived.
      expect(f.release(_stranger, 4 * 60 * 1000), isEmpty);
    });

    test('the pending buffer cannot grow without bound', () {
      for (var i = 0; i < 500; i++) {
        f.hold(
          _post('post $i', pubkey: i.toRadixString(16).padLeft(64, '0')),
          1000,
        );
      }
      expect(
        f.pendingNow,
        lessThanOrEqualTo(400),
        reason:
            'a firehose meets an endless supply of unknown authors — the '
            'hold buffer must be bounded or it is a memory leak',
      );
    });

    test('the same text from a DIFFERENT author is a copy-paste ring', () {
      const text = 'claim your free airdrop before it is too late friends';
      expect(run(_post(text, pubkey: _alice)), isA<FeedKeep>());
      final v = run(_post(text, pubkey: _bob));
      expect((v as FeedReject).reason, FeedDrop.duplicate);
    });

    test('the same text from the SAME author is not a ring', () {
      const text =
          'reminder: the meetup is at seven, upstairs at the usual bar';
      expect(run(_post(text, pubkey: _alice)), isA<FeedKeep>());
      expect(
        run(_post(text, pubkey: _alice)),
        isA<FeedKeep>(),
        reason:
            'a person repeating themselves is covered by the flood rule, '
            'not by the bot-ring rule',
      );
    });

    test('"gm" from a thousand people is not a duplicate', () {
      expect(run(_post('gm', pubkey: _alice)), isA<FeedKeep>());
      expect(
        run(_post('gm', pubkey: _bob)),
        isA<FeedKeep>(),
        reason: 'short greetings collide by nature; only real text counts',
      );
    });

    test('an author posting five times a minute is flooding', () {
      for (var i = 0; i < 4; i++) {
        expect(
          run(_post('post number $i', pubkey: _alice), nowMs: i * 1000),
          isA<FeedKeep>(),
        );
      }
      final v = run(_post('post number five', pubkey: _alice), nowMs: 5000);
      expect((v as FeedReject).reason, FeedDrop.flooding);
    });

    test('yesterday\'s posts do not count against today\'s rate', () {
      for (var i = 0; i < 4; i++) {
        run(_post('post $i', pubkey: _alice), nowMs: i * 1000);
      }
      // Two minutes later the window has moved on.
      expect(
        run(_post('a new thought', pubkey: _alice), nowMs: 130 * 1000),
        isA<FeedKeep>(),
      );
    });

    test('our own posts and the people we follow bypass every rule', () {
      // Would be hashtag-stuffed spam from a stranger; from a friend it is just
      // a bad post, and hiding a followed person is never acceptable.
      final ugly = '#a #b #c #d #e #f #g #h buy';
      expect(run(_post(ugly, pubkey: _me)), isA<FeedKeep>());
      expect(run(_post(ugly, pubkey: _friend)), isA<FeedKeep>());
      // No profile? Still fine — we chose to follow them.
      expect(run(_post('hi', pubkey: _friend)), isA<FeedKeep>());
    });

    test('a muted author never appears', () {
      final v = f.verdict(
        _post('anything at all', pubkey: _alice),
        hasProfile: known.contains,
        trusted: (_) => false,
        muted: (_) => true,
        nowMs: 0,
      );
      expect((v as FeedReject).reason, FeedDrop.muted);
    });

    test('moderate mode (requireProfile off) keeps profile-less strangers', () {
      f = FirehoseFilter(requireProfile: false);
      expect(
        run(_post('hello from a new account', pubkey: _stranger)),
        isA<FeedKeep>(),
      );
    });

    test('drops are counted by reason for the telemetry line', () {
      run(_post('https://x.example/a'));
      run(_post(''));
      final stats = f.drainStats();
      expect(stats['linkOnly'], 1);
      expect(stats['empty'], 1);
      expect(
        f.drainStats()['linkOnly'],
        isNull,
        reason: 'counters reset on read',
      );
    });
  });
}
