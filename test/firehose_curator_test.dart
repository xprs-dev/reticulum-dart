/*
 * A firehose is not a feed.
 *
 * The relays hand us far more than a phone can render or a person can read — the
 * engine was pushing up to 150 events a second at a wapp that could take 26, so
 * the feed spent its life chewing through a backlog while the newest post on
 * screen got older. Draining faster only moves the bottleneck. The fix is to stop
 * pouring: rank what arrived, and hand over the best few, newest-first.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

NostrEvent _post(
  NostrKeyPair kp, {
  String content = 'a perfectly ordinary post about something',
  int at = 1700000000,
  List<List<String>> tags = const [],
}) {
  final e = NostrEvent(
    pubkey: kp.publicKeyHex,
    createdAt: at,
    kind: 1,
    tags: tags,
    content: content,
  );
  e.sign(kp.privateKeyHex);
  return e;
}

const _plain = (
  likes: 0,
  replies: 0,
  hasMedia: false,
  authorHasProfile: false,
  authorSeenBefore: 0,
);

void main() {
  final kp = NostrCrypto.generateKeyPair();
  final nowMs = 1700000000 * 1000;

  test('a post with a picture and engagement beats a bare one', () {
    final c = FirehoseCurator();
    final bare = _post(kp, content: 'gm everyone, hope you have a nice day');
    final good = _post(
      kp,
      content: 'here is the bridge at dawn https://example.com/pic.jpg',
    );

    final bareScore = c.scoreOf(bare, _plain, nowMs);
    final goodScore = c.scoreOf(good, (
      likes: 12,
      replies: 3,
      hasMedia: true,
      authorHasProfile: true,
      authorSeenBefore: 4,
    ), nowMs);

    expect(
      goodScore,
      greaterThan(bareScore),
      reason: 'engagement + a picture + a real profile is what a feed is for',
    );
  });

  test('the newer of two equally good posts wins', () {
    final c = FirehoseCurator();
    final old = _post(
      kp,
      at: 1700000000 - 3600,
      content: 'the same words here',
    );
    final fresh = _post(kp, at: 1700000000, content: 'the same words here');
    expect(
      c.scoreOf(fresh, _plain, nowMs),
      greaterThan(c.scoreOf(old, _plain, nowMs)),
    );
  });

  test('an unengaged promotional link ranks below an ordinary human post', () {
    final c = FirehoseCurator();
    final promo = _post(
      kp,
      content:
          'Celebrity update and exclusive video, read the full story '
          'at https://spam.example/celebrity-exclusive-video',
    );
    final human = _post(
      kp,
      content:
          'I finally got the old radio working after replacing the capacitors',
    );

    expect(
      c.scoreOf(promo, _plain, nowMs),
      lessThan(c.scoreOf(human, _plain, nowMs)),
    );
  });

  test('short unengaged media bait never enters the candidate pool', () {
    final c = FirehoseCurator();
    c.offer(
      _post(
        kp,
        content:
            'file:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.jpg Follow 歩- Ayumi - ジ @Ayumi 歩k 🌸 npub1asjan',
      ),
      (
        likes: 0,
        replies: 0,
        hasMedia: false,
        authorHasProfile: true,
        authorSeenBefore: 0,
      ),
      nowMs,
    );

    expect(c.pending, 0);
  });

  test('substantive unengaged prose remains eligible', () {
    final c = FirehoseCurator();
    final post = _post(
      kp,
      content:
          'I finally got the old radio working after replacing the capacitors',
    );
    c.offer(post, _plain, nowMs);

    expect(c.takeBurst(1).single.id, post.id);
  });

  test('one author gets at most three places before other authors', () {
    final c = FirehoseCurator(maxCandidates: 20);
    for (var i = 0; i < 10; i++) {
      c.offer(
        _post(kp, content: 'loud author post number $i is long enough'),
        _plain,
        nowMs,
      );
    }
    final other = NostrCrypto.generateKeyPair();
    c.offer(
      _post(other, content: 'a quieter person still gets represented'),
      _plain,
      nowMs,
    );

    final out = c.takeBurst(4);
    expect(out.where((e) => e.pubkey == kp.publicKeyHex), hasLength(3));
    expect(out.any((e) => e.pubkey == other.publicKeyHex), isTrue);
  });

  test('the feed is handed a HANDFUL, not the firehose', () {
    final c = FirehoseCurator(perMinute: 12, firstBurst: 5);
    for (var i = 0; i < 200; i++) {
      c.offer(
        _post(kp, content: 'post number $i, which is long enough to read'),
        _plain,
        nowMs,
      );
    }

    final first = c.take(nowMs);
    expect(first, hasLength(5), reason: 'the opening burst fills the tab');

    final second = c.take(nowMs);
    expect(
      second.length,
      lessThanOrEqualTo(4),
      reason: 'after that it advances at a human rate, not 150/s',
    );
    expect(c.pending, greaterThan(100), reason: 'the rest wait their turn');
  });

  test('what comes out is newest-first', () {
    final c = FirehoseCurator(firstBurst: 3);
    c.offer(
      _post(kp, at: 1700000100, content: 'the middle post has useful context'),
      _plain,
      nowMs,
    );
    c.offer(
      _post(kp, at: 1700000200, content: 'the newest post has useful context'),
      _plain,
      nowMs,
    );
    c.offer(
      _post(kp, at: 1700000000, content: 'the oldest post has useful context'),
      _plain,
      nowMs,
    );

    final out = c.take(nowMs);
    expect(out.map((e) => e.createdAt), [1700000200, 1700000100, 1700000000]);
  });

  test('the buffer is bounded, and it is the WORST that is dropped', () {
    final c = FirehoseCurator(maxCandidates: 10);
    // One clearly excellent post, then a flood of mediocre ones.
    final gem = _post(
      kp,
      at: 1700000000,
      content: 'the one worth keeping here',
    );
    c.offer(gem, (
      likes: 50,
      replies: 20,
      hasMedia: true,
      authorHasProfile: true,
      authorSeenBefore: 9,
    ), nowMs);
    for (var i = 0; i < 100; i++) {
      c.offer(
        _post(kp, content: 'filler post number $i goes here'),
        _plain,
        nowMs,
      );
    }

    expect(c.pending, 10, reason: 'bounded — a firehose never stops');
    final out = c.take(nowMs);
    expect(
      out.map((e) => e.id),
      contains(gem.id),
      reason: 'a full buffer drops the worst, never the best',
    );
  });

  test('an empty curator emits nothing', () {
    expect(FirehoseCurator().take(nowMs), isEmpty);
  });

  test('takeBurst returns the best requested batch and removes it', () {
    final c = FirehoseCurator(maxCandidates: 150);
    for (var i = 0; i < 120; i++) {
      c.offer(
        _post(
          kp,
          at: 1700000000 + i,
          content: 'curated batch candidate number $i',
        ),
        _plain,
        nowMs,
      );
    }

    final out = c.takeBurst(100);
    expect(out, hasLength(100));
    expect(c.pending, 20);
    expect(out.first.createdAt, greaterThan(out.last.createdAt));
  });
}
