/*
 * The same directory, the same announces, the same code — and a different answer
 * once the internet is gone (aurora/docs/NOSTR.md, "The score, and why it
 * changes with the weather").
 *
 * The disaster case must not depend on code that only runs during a disaster.
 * So the test is: build ONE directory, ask it twice, and watch the answer move.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:reticulum/src/services/social/node_profile.dart';

Future<RelayEntry> _entry(RelayDirectory dir, RelayAnnouncement a,
    {int hops = 1}) async {
  final id = await RnsIdentity.generate();
  dir.observe(id, a.encode(), hops: hops);
  return dir.byIdentity(id)!;
}

RelayAnnouncement _indexer(NodeProfile p) => RelayAnnouncement(
      role: RelayRole.indexer,
      capacity: 3,
      caps: RelayCap.search | RelayCap.firehose | RelayCap.probe,
      wide: true,
      profile: p,
    );

void main() {
  test('the fibre box on a Tuesday, the solar box the day the grid dies',
      () async {
    final dir = RelayDirectory();

    final fibre = await _entry(
      dir,
      _indexer(const NodeProfile(
        power: PowerSource.grid,
        poweredPct: 99,
        uplink: UplinkKind.fibre,
        bwClass: 26,
      )),
    );

    final solar = await _entry(
      dir,
      _indexer(const NodeProfile(
        power: PowerSource.solarBattery,
        poweredPct: 96,
        uplink: UplinkKind.satellite,
        bwClass: 21,
        links: LinkFlag.lora,
        autonomyHours: 72,
        geohash: 'ezjm',
        radios: [
          RadioEntry(link: LinkFlag.lora, rangeKm: 12, freqKhz: 868200),
        ],
      )),
    );

    final normal = dir.bestIndexer(mode: NetworkMode.normal);
    expect(normal!.idHex, fibre.idHex,
        reason: 'while the internet is up, fast and close wins');

    final degraded = dir.bestIndexer(
      mode: NetworkMode.degraded,
      callerLinks: LinkFlag.lora,
    );
    expect(degraded!.idHex, solar.idHex,
        reason: 'the grid is down: still powered, a path out that no local '
            'infrastructure can take away, and a radio I actually own');
  });

  test('the physical profile survives the announce round-trip in the directory',
      () async {
    final dir = RelayDirectory();
    final e = await _entry(
      dir,
      _indexer(const NodeProfile(
        power: PowerSource.solarBattery,
        uplink: UplinkKind.satellite,
        links: LinkFlag.lora | LinkFlag.packetRadio,
        geohash: 'ezjm',
        radios: [
          RadioEntry(
              link: LinkFlag.packetRadio,
              rangeKm: 80,
              freqKhz: 144800,
              mode: 'AX.25-1200'),
        ],
      )),
    );
    final p = e.announcement.profile;
    expect(p.gridIndependent, isTrue);
    expect(p.uplinkIndependent, isTrue);
    expect(p.reachableOffgrid, isTrue);
    expect(p.geohash, 'ezjm');
    expect(p.radios.single.freqKhz, 144800,
        reason: 'the frequency is what makes the 80 km actionable');
  });

  test('an old node that sends no profile still parses — nobody is broken',
      () async {
    final dir = RelayDirectory();
    final old = RelayAnnouncement(
      role: RelayRole.indexer,
      capacity: 2,
      caps: RelayCap.search,
    );
    final e = await _entry(dir, old);
    expect(e.announcement.profile.power, PowerSource.unknown);
    expect(dir.bestIndexer(), isNotNull);
  });
}
