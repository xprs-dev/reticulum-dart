/*
 * The physical profile and the schedule grammar (aurora/docs/NOSTR.md).
 *
 * The claim these tests exist to defend: a solar-powered node on Starlink with
 * a LoRa antenna is unremarkable on a Tuesday and the most valuable node on the
 * network the day the grid goes down — and a FIXED score cannot express that.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/social/listening_schedule.dart';
import 'package:reticulum/src/services/social/node_profile.dart';

void main() {
  group('the listening schedule', () {
    test('always', () {
      expect(ListeningSchedule.parse('always').isAlways, isTrue);
      expect(ListeningSchedule.parse('').isAlways, isTrue,
          reason: 'a node that said nothing is more likely up than not');
    });

    test('a duty cycle needs no clock — the ESP32 case', () {
      final s = ListeningSchedule.parse('every 10m for 1m');
      expect(s.clockFree, isTrue,
          reason: 'millis() alone can honour this after a reboot');
      expect(s.terms.single, isA<DutyTerm>());
      final d = s.terms.single as DutyTerm;
      expect(d.period, const Duration(minutes: 10));
      expect(d.awake, const Duration(minutes: 1));
      expect(d.dutyFraction, closeTo(0.1, 0.001));
    });

    test('a duty cycle tells a caller how long to keep trying', () {
      final s = ListeningSchedule.parse('every 30m for 3m');
      expect(s.retryWindow, const Duration(minutes: 30),
          reason: 'phase is unknown, so one full period is the guarantee — '
              'giving up after one call is a coin flip');
    });

    test('a clock window is NOT clock-free, and a clockless node must not say it',
        () {
      final s = ListeningSchedule.parse('06:00-18:00');
      expect(s.clockFree, isFalse);
      expect(
          s.listeningAt(DateTime.utc(2026, 7, 13, 9)), isTrue);
      expect(
          s.listeningAt(DateTime.utc(2026, 7, 13, 20)), isFalse);
    });

    test('UTC unless told otherwise — a mesh spans time zones', () {
      final utc = ListeningSchedule.parse('06:00-18:00');
      final loc = ListeningSchedule.parse('06:00-18:00 local');
      final at = DateTime.utc(2026, 7, 13, 19); // 19:00 UTC
      expect(utc.listeningAt(at), isFalse);
      expect(loc.listeningAt(at, tzOffset: const Duration(hours: -3)), isTrue,
          reason: '16:00 where that station lives');
    });

    test('dawn-dusk follows the sun, which is what a solar node actually does',
        () {
      final s = ListeningSchedule.parse('dawn-dusk');
      const winter = SunTimes(dawn: Duration(hours: 9), dusk: Duration(hours: 16));
      expect(s.listeningAt(DateTime.utc(2026, 12, 21, 8), sun: winter), isFalse);
      expect(s.listeningAt(DateTime.utc(2026, 12, 21, 12), sun: winter), isTrue);
      expect(s.listeningAt(DateTime.utc(2026, 12, 21, 17), sun: winter), isFalse,
          reason: 'a hardcoded 06:00-18:00 would have lied here');
    });

    test('solar edges take offsets — a margin to charge', () {
      final s = ListeningSchedule.parse('dawn+30m-dusk-30m');
      const sun = SunTimes(dawn: Duration(hours: 7), dusk: Duration(hours: 19));
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 7, 10), sun: sun), isFalse);
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 7, 40), sun: sun), isTrue);
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 18, 45), sun: sun), isFalse);
    });

    test('days: weekdays, ranges and a Saturday exception', () {
      final s = ListeningSchedule.parse('08:00-20:00 weekdays, 10:00-14:00 sat');
      final monday = DateTime.utc(2026, 7, 13, 9); // a Monday
      final saturday = DateTime.utc(2026, 7, 18, 9);
      final saturdayNoon = DateTime.utc(2026, 7, 18, 12);
      expect(s.listeningAt(monday), isTrue);
      expect(s.listeningAt(saturday), isFalse);
      expect(s.listeningAt(saturdayNoon), isTrue);
    });

    test('the common real case: thrifty all day, wide open in the evening', () {
      final s = ListeningSchedule.parse('every 15m for 2m, 18:00-22:00');
      expect(s.terms, hasLength(2));
      expect(s.clockFree, isFalse);
      expect(s.retryWindow, const Duration(minutes: 15));
    });

    test('a window that wraps midnight', () {
      final s = ListeningSchedule.parse('22:00-04:00');
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 23)), isTrue);
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 2)), isTrue);
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 12)), isFalse);
    });

    test('an unknown term is ignored, never fatal — old nodes survive new words',
        () {
      final s = ListeningSchedule.parse('06:00-18:00, when the tide is in');
      expect(s.terms, hasLength(1));
      expect(s.listeningAt(DateTime.utc(2026, 7, 13, 9)), isTrue);
    });

    test('nextWindow tells a caller when to come back instead of burning a call',
        () {
      final s = ListeningSchedule.parse('06:00-18:00');
      final n = s.nextWindow(DateTime.utc(2026, 7, 13, 3));
      expect(n, isNotNull);
      expect(n!.hour, 6);
    });

    test('it reads back in English for the Settings panel', () {
      expect(describeSchedule(ListeningSchedule.parse('every 30m for 3m')),
          contains('wakes for 3m every 30m'));
      expect(describeSchedule(ListeningSchedule.parse('dawn-dusk')),
          contains('while the sun is up'));
    });
  });

  group('the physical profile', () {
    const solarStarlinkLora = NodeProfile(
      power: PowerSource.solarBattery,
      poweredPct: 96,
      uplink: UplinkKind.satellite,
      bwClass: 22,
      links: LinkFlag.lora | LinkFlag.wifiDirect,
      autonomyHours: 72,
      geohash: 'ezjm',
      radios: [
        RadioEntry(
            link: LinkFlag.lora,
            rangeKm: 12,
            freqKhz: 868200,
            mode: 'LoRa-SF7BW125'),
      ],
    );

    const fibreBox = NodeProfile(
      power: PowerSource.grid,
      poweredPct: 99,
      uplink: UplinkKind.fibre,
      bwClass: 26,
      links: 0,
    );

    const phone = NodeProfile(
      power: PowerSource.batteryOnly,
      poweredPct: 40,
      uplink: UplinkKind.cellular,
      bwClass: 20,
      links: LinkFlag.bluetooth,
    );

    const fresh = Observed(lastHeardSec: 60, hops: 1, heardCount: 9);

    test('round-trips through the announce, radios and all', () {
      final back = NodeProfile.decode(solarStarlinkLora.encode());
      expect(back.power, PowerSource.solarBattery);
      expect(back.uplink, UplinkKind.satellite);
      expect(back.autonomyHours, 72);
      expect(back.geohash, 'ezjm');
      expect(back.radios, hasLength(1));
      expect(back.radios.first.freqKhz, 868200,
          reason: 'a range says it COULD hear you; a frequency says where to call');
      expect(back.radios.first.rangeKm, 12);
    });

    test('the announce stays small — it must never cost a second packet', () {
      expect(solarStarlinkLora.encode().length, lessThan(120));
    });

    test('a phone says nothing about where it sleeps, by default', () {
      expect(NodeProfile.unknown.geohash, isEmpty);
      expect(NodeProfile.unknown.encode().length, lessThan(4));
    });

    test('on a normal Tuesday, the fibre box wins', () {
      final a = scoreNode(fibreBox, fresh, mode: NetworkMode.normal);
      final b = scoreNode(solarStarlinkLora, fresh, mode: NetworkMode.normal);
      expect(a, greaterThan(b),
          reason: 'fast and close is what matters while the internet is up');
    });

    test('the day the grid goes down, solar+starlink+lora wins by a mile', () {
      final a = scoreNode(fibreBox, fresh,
          mode: NetworkMode.degraded, callerLinks: LinkFlag.lora);
      final b = scoreNode(solarStarlinkLora, fresh,
          mode: NetworkMode.degraded, callerLinks: LinkFlag.lora);
      expect(b, greaterThan(a * 2),
          reason: 'a fixed score cannot express this, which is the whole point');
    });

    test('a radio the caller does not own is worth nothing to the caller', () {
      final withLora = scoreNode(solarStarlinkLora, fresh,
          mode: NetworkMode.degraded, callerLinks: LinkFlag.lora);
      final withNone = scoreNode(solarStarlinkLora, fresh,
          mode: NetworkMode.degraded, callerLinks: LinkFlag.packetRadio);
      expect(withLora, greaterThan(withNone),
          reason: 'score per link, not per node');
    });

    test('a phone on cellular is a last resort, and the score says so', () {
      final p = scoreNode(phone, fresh, mode: NetworkMode.normal);
      final f = scoreNode(fibreBox, fresh, mode: NetworkMode.normal);
      expect(p, lessThan(f),
          reason: "somebody is paying for that phone's megabytes");
    });

    test('a stale node is a lottery ticket, whatever it claims about itself',
        () {
      final heard = scoreNode(solarStarlinkLora, fresh,
          mode: NetworkMode.degraded, callerLinks: LinkFlag.lora);
      final silent = scoreNode(
        solarStarlinkLora,
        const Observed(lastHeardSec: 90 * 24 * 3600, hops: 4, heardCount: 1),
        mode: NetworkMode.degraded,
        callerLinks: LinkFlag.lora,
      );
      expect(silent, lessThan(heard),
          reason: 'observed beats claimed, always');
    });

    test('a node cannot announce that it is precious — only what it is', () {
      // There is no "score" field on the wire: the map holds facts only.
      final m = solarStarlinkLora.toMap();
      expect(m.keys, everyElement(isIn(['ps', 'pw', 'up', 'bw', 'lk', 'au', 'gh', 'rx'])));
    });

    test('five radios: the longest-range ones win the space', () {
      const many = NodeProfile(radios: [
        RadioEntry(link: LinkFlag.bluetooth, rangeKm: 1),
        RadioEntry(link: LinkFlag.lora, rangeKm: 12),
        RadioEntry(link: LinkFlag.packetRadio, rangeKm: 80),
        RadioEntry(link: LinkFlag.wifiDirect, rangeKm: 1),
        RadioEntry(link: LinkFlag.serial, rangeKm: 0),
      ]);
      final back = NodeProfile.decode(many.encode());
      expect(back.radios, hasLength(kMaxAnnouncedRadios));
      expect(back.radios.first.rangeKm, 80,
          reason: 'the ones nobody else can substitute');
      expect(back.maxRangeKm, 80);
    });
  });
}
