/*
 * What a node is made of (aurora/docs/NOSTR.md, "The physical profile").
 *
 * Every role — Publisher, Indexer, Archiver — is a promise about SOFTWARE.
 * Whether a node can keep that promise on the worst day of the year is a
 * question about power and antennas. A solar-powered Indexer on Starlink is
 * worth more than a hundred fibre boxes when the grid goes down, and the
 * network has to be able to know that BEFORE it needs it.
 *
 * Two rules keep this honest, and they are the reason the design works:
 *
 *   1. ANNOUNCE FACTS, SCORE LOCALLY. A node never announces "I am precious".
 *      It announces what it IS, and every asker computes its own score. There
 *      is nothing to inflate that would be believed.
 *   2. OBSERVED BEATS CLAIMED. A node claiming 100% powered that we have heard
 *      from twice in a week is scored on the two times we heard it. A
 *      self-reported fact is a hint that saves a measurement, never a
 *      credential.
 *
 * The disaster case must not depend on code that only runs during a disaster:
 * same announce, same directory, same probe — only the WEIGHTS move.
 */
import 'dart:typed_data';

import '../reticulum/lxmf/lxmf_msgpack.dart';
import 'listening_schedule.dart';

/// Where the power comes from. The order is deliberate: lower = more
/// independent of a grid that can fail.
enum PowerSource {
  solarBattery, // panel + bank: still running at night, still running next week
  windHydro,
  solar, // panel, no meaningful storage: daylight only
  gridUps, // grid, but rides through a cut
  grid,
  vehicle, // alternator/leisure battery: mobile, and it moves
  batteryOnly, // a phone. Precious for hours, not days.
  unknown,
}

/// How it reaches the wider world.
enum UplinkKind {
  satellite, // Starlink et al: survives the local ISP, exchange, and flood
  fibre, // wired
  wifi,
  cellular,
  none, // OFFGRID — mesh only, and proud of it
  unknown,
}

/// Radios a node can be reached on, beyond its uplink.
class LinkFlag {
  static const int lora = 1 << 0;
  static const int bluetooth = 1 << 1;
  static const int wifiDirect = 1 << 2;
  static const int packetRadio = 1 << 3; // AX.25 / HF / VHF
  static const int serial = 1 << 4;
  static const int rnsHub = 1 << 5; // a TCP hub it keeps open
}

/// One radio, with its own footprint. A machine with Bluetooth (tens of metres),
/// a LoRa hat (a few km) and a VHF rig (80 km) has THREE footprints, and one
/// number lies about all of them: it makes the Bluetooth look magical and the
/// radio look useless.
class RadioEntry {
  final int link; // a single LinkFlag
  final int rangeKm; // as the person who raised the antenna estimates it
  final int freqKhz; // where it is LISTENING. 0 = not applicable (Bluetooth)
  final String mode; // 'LoRa-SF7BW125', 'AX.25-1200', 'JS8', … free-form
  final ListeningSchedule schedule;

  const RadioEntry({
    required this.link,
    this.rangeKm = 0,
    this.freqKhz = 0,
    this.mode = '',
    this.schedule = ListeningSchedule.always,
  });

  Map<String, dynamic> toMap() => {
        'l': link,
        if (rangeKm > 0) 'r': rangeKm,
        if (freqKhz > 0) 'f': freqKhz,
        if (mode.isNotEmpty) 'm': mode,
        if (!schedule.isAlways) 'd': schedule.text,
      };

  static RadioEntry fromMap(Map m) => RadioEntry(
        link: (m['l'] as num?)?.toInt() ?? 0,
        rangeKm: (m['r'] as num?)?.toInt() ?? 0,
        freqKhz: (m['f'] as num?)?.toInt() ?? 0,
        mode: '${m['m'] ?? ''}',
        schedule: ListeningSchedule.parse(m['d'] as String?),
      );

  /// A range says a station COULD hear you; a frequency says WHERE TO CALL.
  /// Without it, "there is an 80 km packet station over that ridge" is a fact
  /// you cannot act on.
  bool get isActionable => freqKhz > 0 || link == LinkFlag.bluetooth;
}

/// The most radios we will carry in one announce. If a node really has more,
/// the longest-range ones win — those are the ones nobody else can substitute.
const int kMaxAnnouncedRadios = 3;

class NodeProfile {
  final PowerSource power;

  /// Percent of the last 7 days this node actually had power. MEASURED by the
  /// governor, never typed by a human.
  final int poweredPct;

  final UplinkKind uplink;

  /// Measured uplink speed, log-bucketed: bytes/sec ≈ 2^bwClass. 0 = unknown.
  /// An observed number, not a sales figure.
  final int bwClass;

  final int links; // LinkFlag bitmask
  final int autonomyHours; // with no grid and no sun. 0 = unknown.

  /// A COARSE geohash of the region this node serves. Empty = says nothing about
  /// where it is, which is the default for a phone: a device in someone's pocket
  /// has no business advertising where it sleeps. This is for infrastructure
  /// that WANTS to be found — the gateway on the hill, the box on the community
  /// centre roof — which gains everything by being locatable and risks nothing.
  final String geohash;

  final List<RadioEntry> radios;

  const NodeProfile({
    this.power = PowerSource.unknown,
    this.poweredPct = 0,
    this.uplink = UplinkKind.unknown,
    this.bwClass = 0,
    this.links = 0,
    this.autonomyHours = 0,
    this.geohash = '',
    this.radios = const [],
  });

  static const NodeProfile unknown = NodeProfile();

  bool has(int link) => links & link != 0;

  /// Power that does not come from a grid somebody else has to keep running.
  bool get gridIndependent =>
      power == PowerSource.solarBattery ||
      power == PowerSource.windHydro ||
      power == PowerSource.solar ||
      power == PowerSource.vehicle;

  /// A path OUT that does not depend on any infrastructure between here and the
  /// horizon. Starlink survives the local ISP, the local exchange, the flood.
  bool get uplinkIndependent => uplink == UplinkKind.satellite;

  /// Reachable with no internet at all — from a phone with no signal, over
  /// kilometres, on a battery.
  bool get reachableOffgrid =>
      has(LinkFlag.lora) ||
      has(LinkFlag.packetRadio) ||
      has(LinkFlag.bluetooth) ||
      has(LinkFlag.wifiDirect);

  /// The furthest this node claims to reach on any radio, km. A claim, not a
  /// credential — whether it answers is the only real evidence.
  int get maxRangeKm =>
      radios.fold(0, (m, r) => r.rangeKm > m ? r.rangeKm : m);

  Map<String, dynamic> toMap() => {
        if (power != PowerSource.unknown) 'ps': power.index,
        if (poweredPct > 0) 'pw': poweredPct,
        if (uplink != UplinkKind.unknown) 'up': uplink.index,
        if (bwClass > 0) 'bw': bwClass,
        if (links != 0) 'lk': links,
        if (autonomyHours > 0) 'au': autonomyHours,
        if (geohash.isNotEmpty) 'gh': geohash,
        if (radios.isNotEmpty)
          'rx': [
            for (final r in _longestFirst(radios).take(kMaxAnnouncedRadios))
              r.toMap()
          ],
      };

  static List<RadioEntry> _longestFirst(List<RadioEntry> rs) =>
      [...rs]..sort((a, b) => b.rangeKm.compareTo(a.rangeKm));

  static NodeProfile fromMap(Map? m) {
    if (m == null) return unknown;
    return NodeProfile(
      power: _enum(PowerSource.values, m['ps'], PowerSource.unknown),
      poweredPct: ((m['pw'] as num?)?.toInt() ?? 0).clamp(0, 100),
      uplink: _enum(UplinkKind.values, m['up'], UplinkKind.unknown),
      bwClass: (m['bw'] as num?)?.toInt() ?? 0,
      links: (m['lk'] as num?)?.toInt() ?? 0,
      autonomyHours: (m['au'] as num?)?.toInt() ?? 0,
      geohash: '${m['gh'] ?? ''}',
      radios: [
        for (final r in (m['rx'] as List? ?? const []))
          if (r is Map) RadioEntry.fromMap(r)
      ],
    );
  }

  Uint8List encode() => msgpackEncode(toMap());

  static NodeProfile decode(Uint8List? b) {
    if (b == null || b.isEmpty) return unknown;
    try {
      final m = msgpackDecode(b);
      return m is Map ? fromMap(m) : unknown;
    } catch (_) {
      return unknown;
    }
  }

  static T _enum<T>(List<T> values, dynamic raw, T fallback) {
    final i = (raw as num?)?.toInt();
    if (i == null || i < 0 || i >= values.length) return fallback;
    return values[i];
  }
}

/// What we have OBSERVED about a peer, as opposed to what it told us. Observed
/// always beats claimed.
class Observed {
  /// Seconds since we last actually heard from it. Large = a lottery ticket.
  final int lastHeardSec;

  /// Hops away, from the announce.
  final int hops;

  /// How many times we have heard it (a node claiming 100% uptime that we have
  /// heard twice in a week is scored on the twice).
  final int heardCount;

  const Observed({this.lastHeardSec = 0, this.hops = 1, this.heardCount = 1});
}

/// Which world we are scoring for.
///
/// NORMAL: the internet is up, and what matters is fast and close.
/// DEGRADED: no relay, no hub, nothing answering — now it is a survivability
/// question, and the weights invert.
enum NetworkMode { normal, degraded }

/// Score a peer for a caller that owns [callerLinks] (a LinkFlag bitmask).
///
/// The caller's own radios matter: a neighbour's 80 km HF entry is worth NOTHING
/// to someone who only owns LoRa, while its 6 km LoRa entry is worth everything.
/// Score per link, not per node.
int scoreNode(
  NodeProfile p,
  Observed o, {
  required NetworkMode mode,
  int callerLinks = 0,
}) {
  var s = 0;

  // Freshness is the one signal that counts in both worlds: a node we have not
  // heard from is a guess, whatever it claims about itself.
  if (o.lastHeardSec < 300) {
    s += 200;
  } else if (o.lastHeardSec < 3600) {
    s += 80;
  } else if (o.lastHeardSec < 86400) {
    s += 20;
  }
  s -= o.hops * 10;

  if (mode == NetworkMode.normal) {
    // Fast and close. A fibre box wins, as it should on a Tuesday.
    s += p.bwClass * 8; // observed throughput
    if (p.uplink == UplinkKind.fibre) s += 60;
    if (p.uplink == UplinkKind.wifi) s += 40;
    if (p.uplink == UplinkKind.satellite) s += 30;
    if (p.uplink == UplinkKind.cellular) s -= 40; // someone pays per megabyte
    s += (p.poweredPct * 0.5).round();
    return s;
  }

  // DEGRADED. Nothing matters if it is dark.
  if (p.gridIndependent) s += 500;
  if (p.power == PowerSource.solarBattery) s += 150; // still up at night
  if (p.autonomyHours >= 24) s += 120;
  if (p.autonomyHours >= 72) s += 80;

  // A path out that no local infrastructure can take away.
  if (p.uplinkIndependent) s += 400;

  // Reachable with no internet at all — but only on a radio the CALLER has.
  if (callerLinks != 0) {
    final shared = p.links & callerLinks;
    if (shared != 0) {
      s += 300;
      // The radios we can actually use, weighted by how far they reach and
      // whether they told us where to call.
      for (final r in p.radios) {
        if (r.link & callerLinks == 0) continue;
        s += r.rangeKm.clamp(0, 100);
        if (r.isActionable) s += 40; // a frequency, not just a claim of range
      }
    }
  } else if (p.reachableOffgrid) {
    s += 100; // reachable by SOMEBODY, just maybe not by us
  }

  // It was there yesterday, and the day before. Observed, then claimed.
  s += (p.poweredPct * 1.5).round();
  if (o.heardCount >= 5) s += 60;

  // Speed still counts, far below all of the above: a slow node that exists
  // beats a fast node that is a brick.
  s += p.bwClass;
  return s;
}
