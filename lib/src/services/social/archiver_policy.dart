/*
 * The Archiver (aurora/docs/NOSTR.md).
 *
 * Pointers are worthless if every copy they point at is asleep or gone. Somebody
 * has to be willing to hold OTHER PEOPLE'S bytes — and that is a separate,
 * explicit, quota-bound offer, never an accident of having volunteered to index.
 *
 * An Archiver:
 *   - takes a quota from its owner ("30 GB, no more") and never exceeds it;
 *   - chooses what it takes: authors it follows, topics it cares about, or
 *     whatever arrives over a DIRECT LINK (LAN, Bluetooth, LoRa) — the peers
 *     with no route to anywhere, whose data would otherwise die with them;
 *   - mirrors the small devices around it and then publishes ITSELF as a
 *     provider, so the DHT starts pointing at the mains-powered box instead of
 *     waking somebody's phone;
 *   - and never touches its owner's own data to make room.
 *
 * It is not a backup service and it makes no promise to any individual. It is
 * redundancy: with a handful of Archivers around an author, that author survives
 * the loss of any one machine — including their own.
 */
import 'retention_tier.dart';

/// Where a request came from. The transport is not a detail here — it is the
/// policy: a peer that reached us over Bluetooth has no route to anywhere else,
/// and a LoRa gateway wants a very different deal from a LAN box (tiny,
/// precious, slow).
enum ArrivedOver {
  /// Reticulum over the internet / a hub. The peer has other options.
  internet,

  /// Same LAN. Cheap, fast, and the peer is probably a neighbour's device.
  lan,

  /// Bluetooth / BLE. Short range: this peer is physically HERE.
  bluetooth,

  /// LoRa or packet radio. Slow and precious; the sender paid for every byte.
  radio,

  /// Wi-Fi Direct.
  wifiDirect,
}

/// True when the peer has no route to anywhere except through us. Data handed
/// to us on these links is data that dies if we refuse it.
bool isDirectLink(ArrivedOver a) =>
    a == ArrivedOver.lan ||
    a == ArrivedOver.bluetooth ||
    a == ArrivedOver.radio ||
    a == ArrivedOver.wifiDirect;

/// What the owner agreed to hold for other people. Every field is a number the
/// user chose; nothing here is inferred, and nothing here is unbounded.
class ArchiverPolicy {
  /// Hold at most this many bytes for OTHERS. The owner's own data is not in
  /// this budget and is never evicted to make room in it.
  final int quotaBytes;

  /// Redundancy for the people this user already cares about. The default,
  /// because it is the one choice that needs no explanation.
  final bool keepFollowedAuthors;

  /// Topics this Archiver volunteers for (lower-case).
  final Set<String> topics;

  /// Accept whatever arrives over these links — the store-and-forward offer.
  /// A peer with no route to anywhere hands us its data, we hold it, and we pass
  /// it on when the far side appears.
  final Set<ArrivedOver> acceptFrom;

  /// Pull what battery-powered peers are willing to share, then publish
  /// ourselves as a provider so the DHT stops waking them.
  final bool mirrorSmallDevices;

  const ArchiverPolicy({
    this.quotaBytes = 0,
    this.keepFollowedAuthors = true,
    this.topics = const {},
    this.acceptFrom = const {},
    this.mirrorSmallDevices = false,
  });

  /// A device that has not volunteered. Holds nothing for anybody, and says so.
  static const ArchiverPolicy none = ArchiverPolicy();

  bool get isArchiving => quotaBytes > 0;

  bool acceptsFrom(ArrivedOver a) => acceptFrom.contains(a);
}

/// Why a deposit was refused. The reason travels back to the peer: a node that
/// goes silent when it is full teaches its neighbours nothing, and they keep
/// trying.
class ArchiveVerdict {
  final bool accept;
  final String? reason;
  const ArchiveVerdict.yes()
      : accept = true,
        reason = null;
  const ArchiveVerdict.no(this.reason) : accept = false;
}

/// Should this Archiver hold [bytes] of [tier] content, offered by a peer that
/// reached us over [via], referencing [topics]?
///
/// The order of the checks is the design:
///
///  1. **Not volunteered → no.** Silence is not consent, and a device that never
///     said yes must never be quietly enlisted.
///  2. **The quota is a ceiling, not a target.** Full is full.
///  3. **A direct-link peer gets in on the strength of the link alone.** It has
///     nowhere else to go; that is the whole point of the offer, and refusing it
///     because we do not follow the author would defeat it.
///  4. **Otherwise: only what the owner said yes to** — their follows, their
///     topics. An Archiver is not an open dumpster.
ArchiveVerdict admitToArchive({
  required ArchiverPolicy policy,
  required Tier tier,
  required int bytes,
  required int usedBytes,
  required ArrivedOver via,
  Iterable<String> topics = const [],
  bool authorFollowed = false,
}) {
  // Our own content is not "archiving for others" and is not governed here.
  if (tier == Tier.self) return const ArchiveVerdict.yes();

  if (!policy.isArchiving) {
    return const ArchiveVerdict.no('not an archiver');
  }
  if (bytes <= 0) return const ArchiveVerdict.no('empty');
  if (usedBytes + bytes > policy.quotaBytes) {
    return const ArchiveVerdict.no('archive full');
  }

  // The peer that has nowhere else to go. This is the reason the role exists on
  // a LoRa gateway or a box in a village hall: it accepts what it is handed,
  // holds it, and passes it on when the far side appears.
  if (isDirectLink(via) && policy.acceptsFrom(via)) {
    return const ArchiveVerdict.yes();
  }

  if (policy.keepFollowedAuthors && (authorFollowed || tier == Tier.followed)) {
    return const ArchiveVerdict.yes();
  }
  for (final t in topics) {
    if (policy.topics.contains(t.toLowerCase())) {
      return const ArchiveVerdict.yes();
    }
  }
  return const ArchiveVerdict.no('not something this archiver volunteered for');
}
