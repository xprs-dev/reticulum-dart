/*
 * RelayRole / RelayDirectory — the self-organizing layer of the distributed
 * relay (slice 3). Nodes ANNOUNCE what they are and what they hold; peers
 * collect those announcements into a directory and route each query to the
 * indexer most likely to answer it.
 *
 * Role is derived from device capacity (capacity_policy.dart's CapacityProfile,
 * itself driven by capacity_governor.dart from battery + network): a node on
 * unlimited power+bandwidth becomes an INDEXER (search + firehose + store-and-
 * forward; the very-high-capacity ones widen toward a full ARCHIVE); everything
 * else stays a LEAF (consumer + opportunistic light serving). Each indexer
 * advertises an INTEREST SET — the topics/authors it aggregates — so the network
 * shards by interest instead of every node holding everything (the hybrid model).
 *
 * The role/interest summary rides the relay announce's app_data as a compact
 * msgpack blob (reuse lxmf_msgpack). Headless: no Flutter imports — it consumes a
 * CapacityProfile; the live CapacityGovernor wiring lives in rns_service.
 */
import 'dart:typed_data';

import '../reticulum/lxmf/lxmf_msgpack.dart';
import '../reticulum/rns_identity.dart';
import '../files/capacity_policy.dart';
import '../files/dht/provider_record.dart'
    show kCapArchive, kCapHomeFiber, kCapUnknown;
import 'node_profile.dart';

enum RelayRole { leaf, indexer }

/// Capability bit-flags advertised by a node (what it offers to the network).
class RelayCap {
  static const int search = 1 << 0; // answers REQ/SEARCH queries
  static const int firehose = 1 << 1; // keeps a recent firehose window
  static const int storeForward = 1 << 2; // holds offline messages (propagation)
  static const int archive = 1 << 3; // attempts wide/full replication

  /// Answers connectionless NOSTR probes (NPD) — a query needs no link, and a
  /// node with nothing to say answers with silence. Advertised so a querier
  /// never has to guess or wait on a timeout: peers without this bit keep
  /// getting links exactly as before, so old and new nodes interoperate.
  static const int probe = 1 << 4;
}

// Wire caps so a single relay announce stays well within the ~350B app_data
// budget (announce overhead is ~148B inside the 500B MTU).
const int kMaxAnnouncedTopics = 24;
const int kMaxAnnouncedAuthors = 16;
const int _kAuthorPrefixHexLen = 8; // 4 bytes of pubkey is enough to shard

/// The topics/authors a node aggregates (its own interests + its community's).
/// An indexer with [wide] holds everything it sees, ignoring the interest set.
class InterestSet {
  final Set<String> topics = {};
  final Set<String> authors = {}; // full pubkey hex
  bool wide = false;

  void addTopic(String t) {
    if (t.isNotEmpty) topics.add(t.toLowerCase());
  }

  void addAuthor(String pubkeyHex) {
    if (pubkeyHex.isNotEmpty) authors.add(pubkeyHex.toLowerCase());
  }

  /// Does this node want to hold an event with these topics / this author?
  bool covers({Iterable<String> topics = const [], String? author}) {
    if (wide) return true;
    for (final t in topics) {
      if (this.topics.contains(t.toLowerCase())) return true;
    }
    if (author != null && authors.contains(author.toLowerCase())) return true;
    return false;
  }
}

/// What a node advertises about itself in the relay announce app_data.
class RelayAnnouncement {
  final int version;
  final RelayRole role;
  final int capacity; // kCap* class
  final int caps; // RelayCap bit-flags
  final bool wide; // attempts full archive
  final List<String> topics; // interest topics (capped)
  final List<String> authorPrefixes; // 4-byte pubkey prefixes (hex, capped)
  final String? pubkey; // this node's own NOSTR pubkey (hex), for profile fetch
  final int uptimeSeconds; // seconds since this node's RNS stack started (0=n/a)

  /// What this node is MADE OF: power, uplink, radios, coverage. Facts only —
  /// a node never announces that it is precious, it announces what it is, and
  /// every asker scores it locally (node_profile.dart). Empty on a node that
  /// has nothing to declare, which is a phone's default.
  final NodeProfile profile;

  const RelayAnnouncement({
    this.version = 1,
    required this.role,
    required this.capacity,
    required this.caps,
    this.wide = false,
    this.topics = const [],
    this.authorPrefixes = const [],
    this.pubkey,
    this.uptimeSeconds = 0,
    this.profile = NodeProfile.unknown,
  });

  bool has(int cap) => caps & cap != 0;
  bool get isIndexer => role == RelayRole.indexer;

  /// Build the announcement for [profile] + [interests] using the standard
  /// capacity→role mapping. Topics/authors are taken from the interest set
  /// (capped); a wide indexer advertises [RelayCap.archive].
  factory RelayAnnouncement.forCapacity(
      CapacityProfile profile, InterestSet interests,
      {String? pubkey, NodeProfile node = NodeProfile.unknown}) {
    if (!profile.servingAllowed) {
      return RelayAnnouncement(
          role: RelayRole.leaf,
          capacity: profile.capacity,
          // A leaf serves nothing to the network, but it DOES answer queries
          // about its own posts — that is why it accepts inbound links today.
          // Advertising probe support is what makes peers stop opening those
          // links: exactly the node that can least afford handshakes.
          caps: RelayCap.probe,
          pubkey: pubkey,
          profile: node);
    }
    // Only unlimited (charger + WiFi/Ethernet) nodes take the indexer role.
    if (!profile.unlimited) {
      return RelayAnnouncement(
          role: RelayRole.leaf,
          capacity: profile.capacity,
          // A leaf serves nothing to the network, but it DOES answer queries
          // about its own posts — that is why it accepts inbound links today.
          // Advertising probe support is what makes peers stop opening those
          // links: exactly the node that can least afford handshakes.
          caps: RelayCap.probe,
          pubkey: pubkey,
          profile: node);
    }
    var caps = RelayCap.search |
        RelayCap.firehose |
        RelayCap.storeForward |
        RelayCap.probe;
    // Top-tier (pinned archive / home fiber) widen toward a full archive.
    final wide = interests.wide || profile.capacity <= kCapHomeFiber;
    if (wide) caps |= RelayCap.archive;
    return RelayAnnouncement(
      role: RelayRole.indexer,
      capacity: profile.capacity,
      caps: caps,
      wide: wide,
      pubkey: pubkey,
      profile: node,
      topics: wide
          ? const []
          : interests.topics.take(kMaxAnnouncedTopics).toList(),
      authorPrefixes: wide
          ? const []
          : interests.authors
              .take(kMaxAnnouncedAuthors)
              .map((a) => a.length >= _kAuthorPrefixHexLen
                  ? a.substring(0, _kAuthorPrefixHexLen)
                  : a)
              .toList(),
    );
  }

  /// Encode for the relay announce app_data. [uptimeSeconds] overrides the field
  /// when set (>0) — the sender stamps its LIVE uptime here on each announce
  /// (uptime grows over time, so it isn't baked into the cached announcement).
  Map<String, dynamic> get profileMap => profile.toMap();

  Uint8List encode({int uptimeSeconds = 0}) {
    final up = uptimeSeconds > 0 ? uptimeSeconds : this.uptimeSeconds;
    return msgpackEncode({
      'v': version,
      'r': role.index,
      'c': capacity,
      'f': caps,
      'w': wide,
      't': topics,
      'a': authorPrefixes,
      if (pubkey != null && pubkey!.isNotEmpty) 'p': pubkey,
      if (up > 0) 'u': up,
      // The physical profile rides in the SAME announce — it must never cost a
      // second packet, so it is a compact map and the radios are capped.
      if (profileMap.isNotEmpty) 'n': profileMap,
    });
  }

  /// Decode relay app_data, or null if it isn't a relay announcement.
  static RelayAnnouncement? decode(Uint8List? appData) {
    if (appData == null || appData.isEmpty) return null;
    try {
      final m = msgpackDecode(appData);
      if (m is! Map) return null;
      final r = m['r'];
      final c = m['c'];
      if (r is! int || c is! int) return null;
      List<String> strs(Object? v) =>
          v is List ? [for (final e in v) e.toString()] : const [];
      return RelayAnnouncement(
        version: m['v'] is int ? m['v'] as int : 1,
        role: r == RelayRole.indexer.index ? RelayRole.indexer : RelayRole.leaf,
        capacity: c,
        caps: m['f'] is int ? m['f'] as int : 0,
        wide: m['w'] == true,
        topics: strs(m['t']),
        authorPrefixes: strs(m['a']),
        pubkey: m['p'] is String ? m['p'] as String : null,
        uptimeSeconds: m['u'] is int ? m['u'] as int : 0,
        profile: NodeProfile.fromMap(m['n'] is Map ? m['n'] as Map : null),
      );
    } catch (_) {
      return null;
    }
  }

  /// Does this indexer EXPLICITLY list these topics / this author in its
  /// interest set (not merely via a wide/archive catch-all)? Used to prefer a
  /// specialist over a full archive when routing a query.
  bool explicitlyCovers({Iterable<String> topics = const [], String? author}) {
    for (final t in topics) {
      if (this.topics.contains(t.toLowerCase())) return true;
    }
    if (author != null && author.length >= _kAuthorPrefixHexLen) {
      final pfx = author.substring(0, _kAuthorPrefixHexLen).toLowerCase();
      if (authorPrefixes.any((p) => p.toLowerCase() == pfx)) return true;
    }
    return false;
  }

  /// Would this advertised indexer hold an event with these topics/author?
  bool wouldHold({Iterable<String> topics = const [], String? author}) =>
      wide ||
      has(RelayCap.archive) ||
      explicitlyCovers(topics: topics, author: author);
}

/// One observed peer relay.
class RelayEntry {
  final RnsIdentity identity;
  final RelayAnnouncement announcement;
  final int hops;
  int lastSeenMs;

  RelayEntry(this.identity, this.announcement, this.hops, this.lastSeenMs);

  String get idHex =>
      identity.hash.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Collects relay announcements and picks the best indexer for a query.
class RelayDirectory {
  RelayDirectory({this.entryTtl = const Duration(hours: 1), this.clock});

  final Duration entryTtl;

  /// Injectable clock (epoch ms) for tests; defaults to the wall clock.
  int Function()? clock;
  final Map<String, RelayEntry> _entries = {}; // idHex -> entry

  int get _now => clock?.call() ?? DateTime.now().millisecondsSinceEpoch;

  /// Record a peer's relay announcement (parsed from its announce app_data).
  /// Returns the stored entry, or null if [appData] wasn't a relay announcement.
  RelayEntry? observe(RnsIdentity peer, Uint8List? appData, {int hops = 1}) {
    final ann = RelayAnnouncement.decode(appData);
    if (ann == null) return null;
    final e = RelayEntry(peer, ann, hops, _now);
    _entries[e.idHex] = e;
    return e;
  }

  /// The announcement we last heard from [peer], or null. Used to decide whether
  /// a peer can be queried with a connectionless probe (RelayCap.probe) and to
  /// get the NOSTR pubkey the probe is encrypted to — both come from the same
  /// announcement, so a querier never has to guess or wait out a timeout.
  RelayEntry? byIdentity(RnsIdentity peer) {
    final e = _entries[peer.hexHash];
    if (e == null) return null;
    if (_now - e.lastSeenMs > entryTtl.inMilliseconds) return null;
    return e;
  }

  void _expire() {
    final cutoff = _now - entryTtl.inMilliseconds;
    _entries.removeWhere((_, e) => e.lastSeenMs < cutoff);
  }

  /// The RNS identity of a peer that advertised [pubHex] as its own NOSTR key,
  /// so we can query its relay directly (e.g. to fetch its profile). Any role
  /// (leaf or indexer) qualifies — every node answers for its own events.
  RnsIdentity? identityForPubkey(String pubHex) {
    _expire();
    final p = pubHex.toLowerCase();
    for (final e in _entries.values) {
      if (e.announcement.pubkey?.toLowerCase() == p) return e.identity;
    }
    return null;
  }

  /// Every currently-known relay peer (leaf or indexer), freshest first. Each
  /// serves at least its own events, so all are worth querying for backfill.
  List<RelayEntry> entries() {
    _expire();
    return _entries.values.toList()
      ..sort((a, b) => b.lastSeenMs.compareTo(a.lastSeenMs));
  }

  /// All currently-known indexers, freshest first.
  List<RelayEntry> indexers() {
    _expire();
    final list = _entries.values
        .where((e) => e.announcement.isIndexer)
        .toList()
      ..sort((a, b) => b.lastSeenMs.compareTo(a.lastSeenMs));
    return list;
  }

  /// Pick the best indexer to answer a query about [topic]/[author].
  ///
  /// Prefers an indexer whose interest set covers the query, then the physical
  /// profile (node_profile.dart), then fewer hops and freshness.
  ///
  /// [mode] is what makes this design work. On a normal day the weights favour
  /// fast and close, and a fibre box wins. When the internet path is GONE the
  /// weights invert into a survivability question — grid-independent power, a
  /// grid-independent uplink, and radios the caller actually owns — and the
  /// solar box with a LoRa antenna, unremarkable on a Tuesday, becomes the most
  /// valuable node on the network. The disaster case runs the SAME code; only
  /// the weights move.
  RelayEntry? bestIndexer({
    String? topic,
    String? author,
    NetworkMode mode = NetworkMode.normal,
    int callerLinks = 0,
    int? nowMs,
  }) {
    final candidates = indexers();
    if (candidates.isEmpty) return null;
    final topics = topic == null ? const <String>[] : [topic];
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    int score(RelayEntry e) {
      var s = 0;
      // What it is made of, weighed for the world we are actually in. Observed
      // freshness is part of the score, because a node we have not heard from is
      // a guess whatever it claims about itself.
      s += scoreNode(
        e.announcement.profile,
        Observed(
          lastHeardSec: ((now - e.lastSeenMs) ~/ 1000).clamp(0, 1 << 30),
          hops: e.hops,
        ),
        mode: mode,
        callerLinks: callerLinks,
      );
      // Prefer a specialist that explicitly lists the topic/author over a
      // full-archive catch-all, to shard load across the network.
      if (e.announcement.explicitlyCovers(topics: topics, author: author)) {
        s += 1000;
      } else if (e.announcement.wouldHold(topics: topics, author: author)) {
        s += 400; // wide/archive can answer, just less preferred
      }
      // capacity: kCap 1(best)..9(worst) -> contribute (9 - cap) * 20
      final cap = e.announcement.capacity == 0
          ? kCapUnknown
          : e.announcement.capacity;
      s += (kCapUnknown - cap.clamp(kCapArchive, kCapUnknown)) * 20;
      s -= e.hops * 10;
      return s;
    }

    candidates.sort((a, b) {
      final d = score(b).compareTo(score(a));
      if (d != 0) return d;
      return b.lastSeenMs.compareTo(a.lastSeenMs);
    });
    return candidates.first;
  }

  int get size => _entries.length;
  void clear() => _entries.clear();
}

/// Tracks the local role and rebuilds the announcement when capacity changes,
/// invoking [onChanged] so the owner (rns_service) can re-announce. Headless;
/// the owner feeds it CapacityProfile updates from CapacityGovernor.
class RelayRoleManager {
  final InterestSet interests;
  void Function(RelayAnnouncement announcement)? onChanged;

  /// Our own NOSTR pubkey (hex), advertised in announcements so peers can map
  /// our npub → our relay identity and fetch our profile directly.
  String? selfPubkey;

  /// Live uptime (seconds since the RNS stack started), stamped into each
  /// announce so peers can rank stable nodes (likely indexers) first when warm-
  /// starting discovery. Set by the wiring layer; null/0 means "not advertised".
  int Function()? uptimeProvider;

  /// The owner's explicit decision, which OVERRIDES the hardware inference.
  ///
  /// The capacity rule (charger + a real uplink ⇒ indexer) is a good default and
  /// a bad only-option: the old phone in a drawer could never say "yes, use
  /// this", and the metered home line could never say "no, don't". So:
  ///
  ///   'always' — serve as an indexer regardless of what the hardware says
  ///   'off'    — never serve, whatever the charger says
  ///   'auto'   — the hardware decides (the default)
  ///
  /// Without this, picking "Always" changed a preference and nothing else: the
  /// announce still said leaf, peers still filed us as a leaf, and no indexer
  /// ever synced with us.
  String volunteer = 'auto';

  /// What this device is physically made of (power, uplink, radios, coverage).
  /// The host owns it: some of it is measured (powered fraction, throughput),
  /// and some only a human can know — nothing on Android reports that there is
  /// a solar panel on the roof. Re-read on every re-announce, so plugging in a
  /// LoRa hat or moving to Starlink shows up without a restart.
  NodeProfile Function()? nodeProfileProvider;

  NodeProfile get _node => nodeProfileProvider?.call() ?? NodeProfile.unknown;

  RelayAnnouncement _current;

  RelayRoleManager({
    InterestSet? interests,
    CapacityProfile? initial,
    this.selfPubkey,
    this.uptimeProvider,
    this.nodeProfileProvider,
    this.onChanged,
  })  : interests = interests ?? InterestSet(),
        _current = RelayAnnouncement.forCapacity(
            initial ??
                const CapacityProfile(
                    capacity: kCapUnknown,
                    servingAllowed: false,
                    unlimited: false,
                    dailyBudgetBytes: 0),
            interests ?? InterestSet(),
            pubkey: selfPubkey);

  /// Fold the owner's decision into the hardware picture, so the rest of the
  /// derivation (caps, wide, capacity class) stays in ONE place.
  CapacityProfile _withVolunteer(CapacityProfile p) {
    switch (volunteer) {
      case 'always':
        return CapacityProfile(
          capacity: p.capacity,
          servingAllowed: true,
          unlimited: true, // the owner said so; that is the whole point
          dailyBudgetBytes: p.dailyBudgetBytes,
        );
      case 'off':
        return CapacityProfile(
          capacity: p.capacity,
          servingAllowed: false,
          unlimited: false,
          dailyBudgetBytes: 0,
        );
      default:
        return p;
    }
  }

  RelayAnnouncement get current => _current;
  Uint8List announcementAppData() =>
      _current.encode(uptimeSeconds: uptimeProvider?.call() ?? 0);

  /// Apply a new capacity profile; re-derive the role and fire [onChanged] if it
  /// (or its capabilities/capacity) changed.
  void applyCapacity(CapacityProfile profile) {
    final effective = _withVolunteer(profile);
    final next = RelayAnnouncement.forCapacity(effective, interests,
        pubkey: selfPubkey, node: _node);
    if (next.role != _current.role ||
        next.caps != _current.caps ||
        next.capacity != _current.capacity ||
        next.wide != _current.wide ||
        next.pubkey != _current.pubkey) {
      _current = next;
      onChanged?.call(next);
    } else {
      _current = next;
    }
  }

  /// Re-derive after the interest set changed (e.g. user followed a new topic).
  void interestsChanged(CapacityProfile profile) {
    _current =
        RelayAnnouncement.forCapacity(profile, interests, pubkey: selfPubkey);
    onChanged?.call(_current);
  }
}
