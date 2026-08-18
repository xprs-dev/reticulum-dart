/*
 * What an Indexer says ABOUT each holder it hands back (aurora/docs/NOSTR.md,
 * "What an Indexer actually answers").
 *
 * An Indexer never says "here is the file". It says "these N devices have it" —
 * and the redundancy is the point, not an accident. But a bare list of pubkeys
 * makes the client guess which one to call, and guessing wrong costs a wasted
 * link, a wasted transmission, or a stranger's cellular data.
 *
 * So each holder comes with what a caller needs to choose well:
 *
 *   lastHeardSec  a holder last seen three weeks ago is a lottery ticket; one
 *                 seen forty seconds ago is a phone call.
 *   provenance    "I heard this MYSELF" vs "another Indexer told me". After a
 *                 sync, freshness is SECOND-HAND, and the age of the information
 *                 is not the age of the device. Both are reported, because a
 *                 client that cannot tell them apart will trust a rumour.
 *   power/uplink  the whole reason the physical profile exists: prefer the box
 *                 on mains and Wi-Fi over the phone on battery and a metered
 *                 plan. Same file, very different cost to the person holding it.
 *   links         which radios it can be reached on, so a caller with only LoRa
 *                 does not pick a holder it has no way to talk to.
 *
 * Six bytes per holder. The hint is a HINT: it is what the answering node
 * believes, not a signed claim by the holder, and it is worth exactly as much as
 * the answering node's honesty. Whether the holder actually serves the bytes is
 * the only real evidence — and a fetch that fails demotes the record anyway.
 */
import 'dart:typed_data';

/// How the answering node came to believe this.
class HintSource {
  /// We heard the holder ourselves (it STOREd with us, or we saw its announce).
  static const int direct = 0;

  /// Another Indexer told us during a sync. The age below is the age of the
  /// INFORMATION, not of the device.
  static const int synced = 1;
}

class HolderHint {
  /// Seconds since the answering node last had evidence of this holder.
  /// Saturating: anything past ~18 hours reports as "very stale".
  final int lastHeardSec;

  /// [HintSource.direct] or [HintSource.synced].
  final int source;

  /// PowerSource index (see node_profile.dart), 15 = unknown.
  final int power;

  /// UplinkKind index, 15 = unknown.
  final int uplink;

  /// LinkFlag bitmask — the radios this holder can be reached on.
  final int links;

  const HolderHint({
    this.lastHeardSec = 0xffff,
    this.source = HintSource.direct,
    this.power = 15,
    this.uplink = 15,
    this.links = 0,
  });

  static const HolderHint unknown = HolderHint();

  bool get isSecondHand => source == HintSource.synced;

  /// 6 bytes: u16 lastHeard(sec, saturating) | u8 source | u8 power<<4|uplink |
  /// u16 links.
  Uint8List encode() {
    final b = ByteData(6)
      ..setUint16(0, lastHeardSec.clamp(0, 0xffff), Endian.big)
      ..setUint8(2, source & 0xff)
      ..setUint8(3, ((power & 0x0f) << 4) | (uplink & 0x0f))
      ..setUint16(4, links & 0xffff, Endian.big);
    return b.buffer.asUint8List();
  }

  static HolderHint decode(Uint8List b, int offset) {
    final d = ByteData.sublistView(b, offset, offset + 6);
    final packed = d.getUint8(3);
    return HolderHint(
      lastHeardSec: d.getUint16(0, Endian.big),
      source: d.getUint8(2),
      power: (packed >> 4) & 0x0f,
      uplink: packed & 0x0f,
      links: d.getUint16(4, Endian.big),
    );
  }

  static const int wireLen = 6;
}

/// Rank holders for a caller: an awake machine on mains and Wi-Fi first, a
/// battery phone on cellular last, and only if nothing else has it.
///
/// A holder on a metered connection is a LAST RESORT, and the network should
/// feel that way to the person carrying it — the reward for volunteering a good
/// machine is that it, and not somebody's phone, is the one that gets called.
///
/// [callerLinks] is the caller's own radio bitmask: a holder reachable only over
/// LoRa is no use to someone who has none. 0 = "I have the internet, judge them
/// on their own merits".
int scoreHolder(HolderHint h, {int capacity = 9, int callerLinks = 0}) {
  var s = 0;

  // Freshness first — and second-hand freshness is discounted, because after a
  // sync the age of the INFORMATION is not the age of the device.
  final age = h.isSecondHand ? h.lastHeardSec * 2 : h.lastHeardSec;
  if (age < 120) {
    s += 300;
  } else if (age < 900) {
    s += 180;
  } else if (age < 3600) {
    s += 90;
  } else if (age < 86400) {
    s += 20;
  }
  if (h.isSecondHand) s -= 30; // a rumour, however fresh, is still a rumour.

  // Capacity class from the record itself: 1 (pinned archive) .. 9 (unknown).
  s += (9 - capacity.clamp(1, 9)) * 25;

  // What it costs the PERSON holding it. This is the whole reason the physical
  // profile exists.
  switch (h.uplink) {
    case 0: // satellite
      s += 40;
    case 1: // fibre
      s += 80;
    case 2: // wifi
      s += 60;
    case 3: // cellular — somebody is paying by the megabyte
      s -= 120;
    case 4: // none: mesh-only, so only reachable by radio
      s += 0;
  }
  switch (h.power) {
    case 0: // solar + battery
    case 1: // wind/hydro
      s += 50;
    case 3: // grid + ups
    case 4: // grid
      s += 40;
    case 6: // battery only — a phone. Precious for hours, not days.
      s -= 80;
  }

  // A holder we have no way of reaching is not a holder.
  if (callerLinks != 0 && h.links != 0 && (h.links & callerLinks) == 0) {
    s -= 200;
  }
  return s;
}
