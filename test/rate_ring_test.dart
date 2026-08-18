/*
 * The requests-per-hour ring (aurora/docs/NOSTR.md, the Indexer dashboard).
 *
 * The property under test is the bucket boundary: an hour that passes with no
 * events must appear as a ZERO, not be skipped — silence is data. And the ring
 * must survive the round trip through a pref string, because a dashboard that
 * resets to zero on every app restart teaches the owner nothing.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/util/rate_ring.dart';

void main() {
  const h = 3600000;
  late int now;
  int clock() => now;

  setUp(() => now = 100 * h + 1234);

  test('counts land in the current hour', () {
    final r = RateRing(clock: clock, nowMs: now);
    r.add();
    r.add(4);
    expect(r.lastHour, 5);
    expect(r.total, 5);
  });

  test('an hour with no events is a zero, not a gap', () {
    final r = RateRing(clock: clock, nowMs: now);
    r.add(10);
    now += 3 * h; // three silent hours pass
    r.add(2);
    final s = r.series(4);
    expect(s, [10, 0, 0, 2],
        reason: 'silence is data — a sparkline must show the quiet hours');
  });

  test('avgPerHour ignores the current partial hour', () {
    final r = RateRing(clock: clock, nowMs: now);
    r.add(6);
    now += h;
    r.add(12);
    now += h;
    r.add(100); // current, partial — flatters nobody
    expect(r.avgPerHour(window: 2), 9.0);
  });

  test('older than the window falls off the end', () {
    final r = RateRing(hours: 4, clock: clock, nowMs: now);
    r.add(7);
    now += 10 * h; // far past the whole window
    expect(r.total, 0);
    expect(r.lastHour, 0);
  });

  test('survives the round trip through a pref string', () {
    final r = RateRing(clock: clock, nowMs: now);
    r.add(3);
    now += h;
    r.add(5);
    final raw = r.encode();

    final back = RateRing.decode(raw, clock: clock, nowMs: now);
    expect(back.lastHour, 5);
    expect(back.series(2), [3, 5]);
  });

  test('a restart later than the ring shifts history into place', () {
    final r = RateRing(clock: clock, nowMs: now);
    r.add(9);
    final raw = r.encode();

    now += 2 * h; // the app was dead for two hours
    final back = RateRing.decode(raw, clock: clock, nowMs: now);
    expect(back.lastHour, 0, reason: 'the current hour is fresh');
    expect(back.series(3), [9, 0, 0],
        reason: 'the old count sits two hours back, where it happened');
  });

  test('garbage decodes to an empty ring, not a crash', () {
    expect(RateRing.decode('not,numbers,at all', clock: clock).total, 0);
    expect(RateRing.decode('', clock: clock).total, 0);
  });
}
