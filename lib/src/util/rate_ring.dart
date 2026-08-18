/*
 * RateRing — a fixed ring of hourly counters (aurora/docs/NOSTR.md, the
 * Indexer dashboard).
 *
 * "Requests per hour" is the number that tells an Indexer's owner whether the
 * offer is being used at all. Nothing in the stack kept it: counters were
 * lifetime totals, so a device up for a month showed a big number and no shape.
 * This is the shape: one bucket per hour, a bounded window, and a series a
 * sparkline can draw.
 *
 * Same family as the powered ring (one sample per hour, persisted as a short
 * string) — pure, headless, unit-testable. The clock is injectable because the
 * bucket boundary IS the behaviour.
 */
class RateRing {
  /// 48 hours: enough for "yesterday vs today" at a glance, small enough that
  /// the persisted form is a short CSV line.
  static const int defaultHours = 48;

  final int hours;
  final int Function()? clock; // epoch ms; injectable for tests

  final List<int> _buckets;
  int _headHour; // absolute hour index (epochMs ~/ 3600000) of _buckets head

  RateRing({this.hours = defaultHours, this.clock, int? nowMs})
      : _buckets = List<int>.filled(hours, 0, growable: true),
        _headHour = ((nowMs ?? DateTime.now().millisecondsSinceEpoch) ~/
            3600000);

  int get _nowMs => clock?.call() ?? DateTime.now().millisecondsSinceEpoch;

  /// Rotate so the head bucket is the current hour. Hours nobody counted in are
  /// zeros — silence is data here, not absence of data.
  void _roll() {
    final h = _nowMs ~/ 3600000;
    var ahead = h - _headHour;
    if (ahead <= 0) return;
    if (ahead >= hours) {
      _buckets.fillRange(0, hours, 0);
      _headHour = h;
      return;
    }
    while (ahead-- > 0) {
      _buckets.removeLast();
      _buckets.insert(0, 0);
      _headHour++;
    }
  }

  /// Count [n] events in the current hour.
  void add([int n = 1]) {
    if (n <= 0) return;
    _roll();
    _buckets[0] += n;
  }

  /// Events counted in the current (partial) hour.
  int get lastHour {
    _roll();
    return _buckets[0];
  }

  /// Average per hour over the most recent [window] FULL buckets (the current
  /// partial hour is excluded — averaging a half-full bucket flatters nobody).
  double avgPerHour({int window = 24}) {
    _roll();
    final w = window.clamp(1, hours - 1);
    var sum = 0;
    for (var i = 1; i <= w; i++) {
      sum += _buckets[i];
    }
    return sum / w;
  }

  /// Everything in the ring, oldest first — a sparkline draws this verbatim.
  List<int> series([int? n]) {
    _roll();
    final take = (n ?? hours).clamp(1, hours);
    return _buckets.sublist(0, take).reversed.toList();
  }

  int get total {
    _roll();
    return _buckets.fold(0, (s, b) => s + b);
  }

  /// Persist: "headHour,b0,b1,…". Short (48 small ints), human-inspectable.
  String encode() {
    _roll();
    return '$_headHour,${_buckets.join(',')}';
  }

  /// Restore from [encode]'s output. A ring older than its own window comes back
  /// empty — correctly: those hours are over. Garbage decodes to an empty ring
  /// rather than a crash; a corrupt pref costs history, not a boot.
  static RateRing decode(String raw,
      {int hours = defaultHours, int Function()? clock, int? nowMs}) {
    final ring = RateRing(hours: hours, clock: clock, nowMs: nowMs);
    try {
      final parts = raw.split(',');
      if (parts.length < 2) return ring;
      final head = int.parse(parts[0]);
      final now = ring._nowMs ~/ 3600000;
      final ahead = now - head;
      if (ahead < 0 || ahead >= hours) return ring;
      for (var i = 0; i + 1 < parts.length && i < hours; i++) {
        final v = int.tryParse(parts[i + 1]) ?? 0;
        final idx = i + ahead;
        if (idx < hours && v > 0) ring._buckets[idx] = v;
      }
      ring._headHour = now;
    } catch (_) {
      // fall through with whatever landed; the ring stays consistent.
    }
    return ring;
  }
}
