/*
 * When a node is listening — one string a person can read and a machine can
 * parse (aurora/docs/NOSTR.md, "The listening schedule").
 *
 *   always
 *   every 30m for 3m
 *   06:00-18:00
 *   06:00-18:00 local
 *   dawn-dusk
 *   dawn+30m-dusk-30m
 *   08:00-20:00 weekdays, 10:00-14:00 sat
 *   every 15m for 2m, 18:00-22:00
 *
 * Solar and battery stations do not hear 24/7 — they wake, listen and sleep. A
 * node only reachable in a window is not broken, it is THRIFTY, and a caller
 * who gives up after one unanswered call has thrown away a good station.
 *
 * Two forms, and the duty form is the normative one:
 *
 *   duty   ("every N for M") needs no clock, no NTP, no calendar — only a
 *          monotonic tick. An ESP32 that just rebooted has no idea what day it
 *          is, but it can honour "1 minute in every 10" from millis() alone.
 *   window ("06:00-18:00", "dawn-dusk") needs a clock, and a node that has none
 *          MUST NOT advertise one: promising a time of day you cannot tell
 *          costs a caller a transmission out of a battery, which is the exact
 *          resource this whole design exists to protect.
 *
 * Times are UTC unless suffixed `local` — a mesh spans time zones, and a station
 * that says 06:00 meaning "my morning" is a station nobody can call.
 */
import 'dart:math' as math;

/// A node with no clock may only ever advertise duty terms. [ListeningSchedule.parse]
/// enforces nothing (a peer may say what it likes); [ListeningSchedule.clockFree]
/// is what a *sender* checks about itself before advertising.
class ListeningSchedule {
  /// The canonical text. This is the format; the packed form is an optimisation.
  final String text;
  final List<ScheduleTerm> terms;

  const ListeningSchedule(this.text, this.terms);

  static const ListeningSchedule always =
      ListeningSchedule('always', [AlwaysTerm()]);

  /// Parse a schedule. Unknown terms are IGNORED rather than fatal, so a future
  /// term (a new keyword, a new qualifier) makes an old node miss one window —
  /// a failure it already knows how to survive — instead of bricking its parser.
  /// Returns [always] when nothing parses, because a node that said *something*
  /// is more likely listening than not.
  static ListeningSchedule parse(String? input) {
    final raw = (input ?? '').trim().toLowerCase();
    if (raw.isEmpty || raw == 'always') return always;

    final terms = <ScheduleTerm>[];
    for (final part in raw.split(',')) {
      final t = _parseTerm(part.trim());
      if (t != null) terms.add(t);
    }
    if (terms.isEmpty) return always;
    return ListeningSchedule(raw, terms);
  }

  /// True when every term is clock-free — the only kind of schedule a node
  /// without an RTC is allowed to advertise.
  bool get clockFree => terms.every((t) => t is DutyTerm);

  bool get isAlways => terms.any((t) => t is AlwaysTerm);

  /// Is this node listening at [at] (UTC)? A duty term has no phase we can know
  /// from the outside, so it answers *maybe* — see [dutyPeriod] and the caller
  /// guidance on [retryWindow].
  bool listeningAt(DateTime at, {Duration? tzOffset, SunTimes? sun}) {
    for (final t in terms) {
      if (t.covers(at, tzOffset: tzOffset ?? Duration.zero, sun: sun)) {
        return true;
      }
    }
    return false;
  }

  /// How long a caller must be willing to keep trying before it may conclude a
  /// station is dead.
  ///
  /// With a duty cycle and no shared clock the PHASE is unknown: we know the
  /// station wakes for M in every N, but not when N started. Trying once and
  /// giving up is therefore a coin flip. Trying across one full period is a
  /// guarantee — so this returns the longest period among the duty terms, and
  /// zero when the schedule is clock-anchored (there, [nextWindow] is exact).
  Duration get retryWindow {
    var worst = Duration.zero;
    for (final t in terms) {
      if (t is DutyTerm && t.period > worst) worst = t.period;
    }
    return worst;
  }

  /// The next instant this node is (or might be) listening, at or after [from].
  /// Null when it cannot be determined (an unbounded search would be a hang).
  DateTime? nextWindow(DateTime from, {Duration? tzOffset, SunTimes? sun}) {
    if (isAlways) return from;
    DateTime? best;
    for (final t in terms) {
      final n = t.next(from, tzOffset: tzOffset ?? Duration.zero, sun: sun);
      if (n == null) continue;
      if (best == null || n.isBefore(best)) best = n;
    }
    return best;
  }

  @override
  String toString() => text;
}

/// Sunrise/sunset for the node's own coverage region — a solar node's real
/// schedule IS the sun, and "dawn-dusk" stays correct in December, which a
/// hardcoded 06:00-18:00 does not.
class SunTimes {
  final Duration dawn; // from local midnight
  final Duration dusk;
  const SunTimes({required this.dawn, required this.dusk});

  /// A serviceable default when the node's region is unknown.
  static const SunTimes unknown =
      SunTimes(dawn: Duration(hours: 7), dusk: Duration(hours: 19));
}

abstract class ScheduleTerm {
  const ScheduleTerm();
  bool covers(DateTime at, {required Duration tzOffset, SunTimes? sun});
  DateTime? next(DateTime from, {required Duration tzOffset, SunTimes? sun});
}

class AlwaysTerm extends ScheduleTerm {
  const AlwaysTerm();
  @override
  bool covers(DateTime at, {required Duration tzOffset, SunTimes? sun}) => true;
  @override
  DateTime? next(DateTime from, {required Duration tzOffset, SunTimes? sun}) =>
      from;
}

/// "every 30m for 3m" — a repeating cycle, needing no clock at all.
class DutyTerm extends ScheduleTerm {
  final Duration period;
  final Duration awake;
  const DutyTerm(this.period, this.awake);

  /// Without a shared clock we cannot know the phase, so from the outside a duty
  /// term is always "possibly listening". The honest caller behaviour is to
  /// retry across one full [period] (see [ListeningSchedule.retryWindow]).
  @override
  bool covers(DateTime at, {required Duration tzOffset, SunTimes? sun}) => true;

  @override
  DateTime? next(DateTime from, {required Duration tzOffset, SunTimes? sun}) =>
      from;

  /// The fraction of time this node is actually awake — useful for ranking a
  /// thrifty station below a generous one when both can serve.
  double get dutyFraction =>
      period.inMilliseconds == 0 ? 1 : awake.inMilliseconds / period.inMilliseconds;

  @override
  String toString() => 'every ${_span(period)} for ${_span(awake)}';
}

/// "06:00-18:00 weekdays", "dawn-dusk", "dawn+30m-dusk-30m".
class WindowTerm extends ScheduleTerm {
  /// Minutes from midnight, or null when the edge is solar.
  final int? startMin;
  final int? endMin;
  final bool startIsDawn;
  final bool endIsDusk;
  final Duration startOffset;
  final Duration endOffset;
  final bool local; // false = UTC
  final Set<int> days; // 1=Mon .. 7=Sun; empty = every day

  const WindowTerm({
    this.startMin,
    this.endMin,
    this.startIsDawn = false,
    this.endIsDusk = false,
    this.startOffset = Duration.zero,
    this.endOffset = Duration.zero,
    this.local = false,
    this.days = const {},
  });

  ({int start, int end}) _bounds(SunTimes? sun) {
    final s = sun ?? SunTimes.unknown;
    final start = startIsDawn
        ? (s.dawn + startOffset).inMinutes
        : (startMin ?? 0) + startOffset.inMinutes;
    final end = endIsDusk
        ? (s.dusk + endOffset).inMinutes
        : (endMin ?? 0) + endOffset.inMinutes;
    return (start: start, end: end);
  }

  @override
  bool covers(DateTime at, {required Duration tzOffset, SunTimes? sun}) {
    final t = local ? at.add(tzOffset) : at;
    if (days.isNotEmpty && !days.contains(t.weekday)) return false;
    final b = _bounds(sun);
    final m = t.hour * 60 + t.minute;
    if (b.start <= b.end) return m >= b.start && m < b.end;
    // Wraps midnight ("22:00-04:00").
    return m >= b.start || m < b.end;
  }

  @override
  DateTime? next(DateTime from, {required Duration tzOffset, SunTimes? sun}) {
    // Bounded search: a schedule that never fires inside a week is a schedule
    // nobody should be waiting on.
    for (var i = 0; i < 8 * 24 * 60; i += 1) {
      final t = from.add(Duration(minutes: i));
      if (covers(t, tzOffset: tzOffset, sun: sun)) return t;
    }
    return null;
  }
}

// ── Parsing ────────────────────────────────────────────────────────────────

ScheduleTerm? _parseTerm(String s) {
  if (s.isEmpty) return null;
  if (s == 'always') return const AlwaysTerm();

  // duty: "every 30m for 3m"
  final duty = RegExp(r'^every\s+(\d+)\s*([mh])\s+for\s+(\d+)\s*([mh])$')
      .firstMatch(s);
  if (duty != null) {
    final period = _dur(int.parse(duty.group(1)!), duty.group(2)!);
    final awake = _dur(int.parse(duty.group(3)!), duty.group(4)!);
    if (period.inMinutes <= 0 || awake <= Duration.zero) return null;
    // Awake longer than the period is just "always", said clumsily.
    if (awake >= period) return const AlwaysTerm();
    return DutyTerm(period, awake);
  }

  // window: "<point>-<point> [days] [local]"
  var rest = s;
  var local = false;
  if (rest.endsWith(' local')) {
    local = true;
    rest = rest.substring(0, rest.length - 6).trim();
  } else if (rest.endsWith(' utc')) {
    rest = rest.substring(0, rest.length - 4).trim();
  }

  final parts = rest.split(' ');
  final range = parts.first;
  final days = parts.length > 1 ? _days(parts.sublist(1).join(' ')) : <int>{};

  final pts = _splitRange(range);
  if (pts == null) return null;
  final a = _point(pts.$1);
  final b = _point(pts.$2);
  if (a == null || b == null) return null;

  return WindowTerm(
    startMin: a.minutes,
    endMin: b.minutes,
    startIsDawn: a.solar == _Solar.dawn,
    endIsDusk: b.solar == _Solar.dusk,
    startOffset: a.offset,
    endOffset: b.offset,
    local: local,
    days: days,
  );
}

/// Split "06:00-18:00" / "dawn+30m-dusk-30m" into its two points. The hyphen is
/// both the range separator AND a negative offset, so we cannot just split on
/// it: find the separator that sits between a complete point and a point start.
(String, String)? _splitRange(String s) {
  for (var i = 1; i < s.length; i++) {
    if (s[i] != '-') continue;
    final left = s.substring(0, i);
    final right = s.substring(i + 1);
    if (right.isEmpty) continue;
    // The right side must BEGIN a point: a digit or a solar keyword.
    if (RegExp(r'^(\d|dawn|dusk|sunrise|sunset)').hasMatch(right) &&
        _point(left) != null &&
        _point(right) != null) {
      return (left, right);
    }
  }
  return null;
}

enum _Solar { none, dawn, dusk }

class _Point {
  final int? minutes;
  final _Solar solar;
  final Duration offset;
  const _Point(this.minutes, this.solar, this.offset);
}

_Point? _point(String raw) {
  var s = raw.trim();
  var offset = Duration.zero;

  final off = RegExp(r'([+-])(\d+)\s*([mh])$').firstMatch(s);
  if (off != null && !RegExp(r'^\d{1,2}:\d{2}$').hasMatch(s)) {
    final sign = off.group(1) == '-' ? -1 : 1;
    offset = _dur(int.parse(off.group(2)!) * sign, off.group(3)!);
    s = s.substring(0, off.start);
  }

  if (s == 'dawn' || s == 'sunrise') return _Point(null, _Solar.dawn, offset);
  if (s == 'dusk' || s == 'sunset') return _Point(null, _Solar.dusk, offset);

  final hm = RegExp(r'^(\d{1,2}):(\d{2})$').firstMatch(s);
  if (hm == null) return null;
  final h = int.parse(hm.group(1)!);
  final m = int.parse(hm.group(2)!);
  if (h > 23 || m > 59) return null;
  return _Point(h * 60 + m, _Solar.none, offset);
}

const _dayNames = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

Set<int> _days(String s) {
  final out = <int>{};
  for (final chunk in s.split(RegExp(r'[\s,]+'))) {
    final c = chunk.trim();
    if (c.isEmpty) continue;
    if (c == 'daily' || c == 'everyday') return {};
    if (c == 'weekdays') {
      out.addAll([1, 2, 3, 4, 5]);
      continue;
    }
    if (c == 'weekends') {
      out.addAll([6, 7]);
      continue;
    }
    final span = c.split('-');
    if (span.length == 2) {
      final a = _dayNames.indexOf(span[0]);
      final b = _dayNames.indexOf(span[1]);
      if (a >= 0 && b >= 0) {
        var i = a;
        while (true) {
          out.add(i + 1);
          if (i == b) break;
          i = (i + 1) % 7;
        }
      }
      continue;
    }
    final d = _dayNames.indexOf(c);
    if (d >= 0) out.add(d + 1);
  }
  return out;
}

Duration _dur(int n, String unit) =>
    unit == 'h' ? Duration(hours: n) : Duration(minutes: n);

String _span(Duration d) => d.inMinutes % 60 == 0 && d.inHours >= 1
    ? '${d.inHours}h'
    : '${d.inMinutes}m';

/// A human sentence for the Settings panel — the picker writes the string, and
/// the panel prints back what it means.
String describeSchedule(ListeningSchedule s) {
  if (s.isAlways) return 'Listening all the time.';
  final bits = <String>[];
  for (final t in s.terms) {
    if (t is DutyTerm) {
      bits.add('wakes for ${_span(t.awake)} every ${_span(t.period)}'
          ' (${(t.dutyFraction * 100).round()}% of the time)');
    } else if (t is WindowTerm) {
      final when = t.startIsDawn && t.endIsDusk
          ? 'while the sun is up'
          : 'from ${_hhmm(t.startMin ?? 0)} to ${_hhmm(t.endMin ?? 0)}'
              '${t.local ? ' local time' : ' UTC'}';
      final days = t.days.isEmpty
          ? 'every day'
          : t.days.map((d) => _dayNames[d - 1]).join(', ');
      bits.add('$when, $days');
    }
  }
  return '${bits.join('; or ')}.';
}

String _hhmm(int minutes) {
  final h = (minutes ~/ 60) % 24;
  final m = math.max(0, minutes % 60);
  return '${h.toString().padLeft(2, '0')}:${m.toString().padLeft(2, '0')}';
}
