/*
 * firehose_curator — a firehose is not a feed.
 *
 * Public relays produce far more than a phone can render or a person can read:
 * the engine was handing the wapp up to 150 events a second, the wapp could take
 * about 26, and so the feed was permanently chewing through a backlog while the
 * newest post on screen got older and older. Draining faster only moves the
 * bottleneck; the answer is to stop pouring.
 *
 * So everything that survives the quality gate (feed_quality.dart — which says
 * what is NOT spam) arrives here, which says what is WORTH SHOWING FIRST. It is a
 * bounded buffer of candidates, and on a timer it emits the best few, newest-first
 * among equals.
 *
 * Every signal is one we already hold locally. No extra network call, no
 * follower-count service (there isn't one in NOSTR anyway) — just what the device
 * has already learned:
 *
 *   * engagement — likes and replies the hub has already tallied;
 *   * pictures — a post with an image is what a feed is for;
 *   * a real profile — an author with a name and a picture is a person, not a bot;
 *   * a face we keep seeing — an author whose posts we have already accepted;
 *   * freshness — of two equally good posts, the newer one wins.
 *
 * People the user FOLLOWS never come through here. They are not candidates to be
 * ranked against strangers; they are the point.
 */
import '../../util/nostr_event.dart';

final RegExp _externalUrl = RegExp(r'https?://\S+', caseSensitive: false);
final RegExp _noteToken = RegExp(
  r'(?:^|\s)(?:#[^\s#]+|@[^\s@]+|nostr:[a-z0-9]+)',
  caseSensitive: false,
);
final RegExp _engagementBait = RegExp(
  r'\b(?:follow|subscribe)\b',
  caseSensitive: false,
);

/// What the hub knows about a candidate, passed in so the curator stays pure and
/// testable — it never reaches into the hub's caches itself.
typedef CandidateSignals = ({
  int likes,
  int replies,
  bool hasMedia,
  bool authorHasProfile,
  int authorSeenBefore,
});

class ScoredPost {
  final NostrEvent event;
  final double score;
  final int atMs;
  const ScoredPost(this.event, this.score, this.atMs);
}

class FirehoseCurator {
  FirehoseCurator({
    this.maxCandidates = 300,
    this.perMinute = 12,
    this.firstBurst = 30,
  });

  /// How many posts we hold, ranked, waiting for their turn. Bounded: a firehose
  /// never stops, and the point is to keep the BEST few, not all of them.
  final int maxCandidates;

  /// How many we hand the feed per minute once it is warm. A person reads a
  /// handful of posts a minute; a phone renders a handful without stuttering.
  final int perMinute;

  /// The first handful, so an opened tab fills at once instead of trickling.
  final int firstBurst;

  final List<ScoredPost> _candidates = [];
  bool _warm = false;

  int get pending => _candidates.length;

  /// Rank a post and hold it. Returns nothing — delivery happens on [take].
  void offer(NostrEvent event, CandidateSignals s, int nowMs) {
    final score = scoreOf(event, s, nowMs);
    // The public firehose is saturated with automated link cards. A link earns
    // a discovery slot only after somebody has liked it or replied to it;
    // ordinary text notes remain eligible immediately.
    if (_externalUrl.hasMatch(event.content) &&
        s.likes == 0 &&
        s.replies == 0) {
      return;
    }
    if (_engagementBait.hasMatch(event.content) &&
        s.likes == 0 &&
        s.replies == 0) {
      return;
    }
    // A fresh profile and an image are both trivial for a bot to manufacture.
    // Without engagement, require enough actual prose to make the post useful:
    // handles, hashtags, NOSTR tokens and URLs do not count. This keeps short
    // "follow @name" media bait out without making English the only language
    // allowed through the firehose.
    if (s.likes == 0 && s.replies == 0) {
      final meaningful = _meaningfulLength(event.content);
      if (s.hasMedia && meaningful < 24) return;
    }
    _candidates.add(ScoredPost(event, score, nowMs));
    // Keep the best. When the buffer is full the WORST candidate goes, not the
    // oldest: a firehose's problem is never a shortage of posts.
    if (_candidates.length > maxCandidates) {
      _candidates.sort((a, b) => a.score.compareTo(b.score));
      _candidates.removeRange(0, _candidates.length - maxCandidates);
    }
  }

  /// The best posts to show now, newest-first among equals. Call on a timer.
  List<NostrEvent> take(int nowMs) {
    if (_candidates.isEmpty) return const [];
    final want = _warm ? _perTick() : firstBurst;
    _warm = true;

    _candidates.sort((a, b) {
      final byScore = b.score.compareTo(a.score);
      if (byScore != 0) return byScore;
      return b.event.createdAt.compareTo(a.event.createdAt);
    });

    final out = _takeDiverse(want);
    return [for (final c in out) c.event];
  }

  /// A pull-to-refresh: the best [n], now. The user asked for more; the timer's
  /// polite trickle is not an answer to that.
  List<NostrEvent> takeBurst(int n) {
    if (_candidates.isEmpty) return const [];
    _warm = true;
    _candidates.sort((a, b) {
      final byScore = b.score.compareTo(a.score);
      if (byScore != 0) return byScore;
      return b.event.createdAt.compareTo(a.event.createdAt);
    });
    final out = _takeDiverse(n);
    return [for (final c in out) c.event];
  }

  /// Prefer breadth over one prolific account. Three posts per author is enough
  /// to represent a voice in a 100-note discovery batch; if the relay window is
  /// unusually thin, a second pass fills the remaining slots rather than
  /// returning an artificially short batch.
  List<ScoredPost> _takeDiverse(int want) {
    final limit = want < _candidates.length ? want : _candidates.length;
    final picked = <ScoredPost>[];
    final deferred = <ScoredPost>[];
    final perAuthor = <String, int>{};
    for (final candidate in _candidates) {
      final count = perAuthor[candidate.event.pubkey] ?? 0;
      if (count >= 3) {
        deferred.add(candidate);
      } else {
        perAuthor[candidate.event.pubkey] = count + 1;
        picked.add(candidate);
      }
      if (picked.length == limit) break;
    }
    if (picked.length < limit) {
      picked.addAll(deferred.take(limit - picked.length));
    }
    final ids = {for (final candidate in picked) candidate.event.id};
    _candidates.removeWhere((candidate) => ids.contains(candidate.event.id));
    return picked;
  }

  /// Emit is called every [tickSeconds]; spread the per-minute allowance across
  /// the ticks so the feed advances steadily rather than in lumps.
  static const int tickSeconds = 10;
  int _perTick() {
    final n = (perMinute * tickSeconds) ~/ 60;
    return n < 1 ? 1 : n;
  }

  /// The ranking itself. Deliberately simple and explainable: if a post is hidden
  /// (or promoted) the reason has to be sayable in one sentence.
  double scoreOf(NostrEvent event, CandidateSignals s, int nowMs) {
    var score = 0.0;

    // Somebody else already thought it was worth something. The strongest signal
    // we have, and the cheapest — it costs the network nothing to tell us.
    score += s.likes * 2.0;
    score += s.replies * 3.0; // a reply is a bigger commitment than a like

    // A feed with pictures in it is a feed people look at.
    if (s.hasMedia) score += 4.0;

    // A name and a picture is the cheapest evidence of a person rather than a
    // script. It is not proof — it is a prior.
    if (s.authorHasProfile) score += 3.0;

    // An author we keep accepting is one this device has already vouched for,
    // repeatedly. Capped, so a prolific account cannot buy the whole feed.
    score += (s.authorSeenBefore > 5 ? 5 : s.authorSeenBefore) * 0.5;

    // Freshness. A great post from an hour ago still loses to a good one from a
    // minute ago — this is a feed, not an archive.
    final ageMin = ((nowMs ~/ 1000) - event.createdAt) / 60.0;
    if (ageMin <= 2) {
      score += 4.0;
    } else if (ageMin <= 10) {
      score += 2.0;
    } else if (ageMin > 60) {
      score -= 3.0;
    }

    // Something to actually read. Not a rule about length — a floor under the
    // one-word posts that survive the spam gate but make a feed feel empty.
    final len = event.content.trim().length;
    if (len >= 80) score += 1.0;
    if (len < 15) score -= 1.0;

    // A profile plus a preview image is cheap for an SEO bot to manufacture.
    // An external link with no engagement is therefore a weak discovery
    // candidate, while a link people actually discussed or liked keeps its
    // earned signal. This demotes promotional link cards without hiding normal
    // conversation that happens to cite a source.
    final urls = _externalUrl.allMatches(event.content).length;
    if (urls > 0 && s.likes == 0 && s.replies == 0) score -= 12.0;
    if (urls > 1) score -= (urls - 1) * 2.0;

    return score;
  }
}

int _meaningfulLength(String content) {
  final prose = content
      .replaceAll(_externalUrl, ' ')
      .replaceAll(_noteToken, ' ')
      .replaceAll(RegExp(r'\s+'), ' ')
      .trim();
  var count = 0;
  for (final rune in prose.runes) {
    if (rune < 128) {
      if ((rune >= 48 && rune <= 57) ||
          (rune >= 65 && rune <= 90) ||
          (rune >= 97 && rune <= 122)) {
        count++;
      }
      continue;
    }
    if (rune >= 0x1F000 ||
        (rune >= 0x2190 && rune <= 0x2BFF) ||
        (rune >= 0x2600 && rune <= 0x27BF) ||
        (rune >= 0xFE00 && rune <= 0xFE0F)) {
      continue;
    }
    count++;
  }
  return count;
}
