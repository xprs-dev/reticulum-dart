/*
 * NostrRelayHub — the one place that manages a user's relay LIST and fans NOSTR
 * traffic across every transport. The wapp/UI talks only to the hub: it manages
 * a list of relay URIs (add/remove, see status) and calls subscribe/publish. The
 * hub picks the transport per URI scheme (wss:// | rns:// | local), merges every
 * inbound event into the ONE local RelayEventStore (verify + dedup), and buffers
 * per-subscription events for the wapp to drain (inbox-pop, the established HAL
 * pattern). Adding a transport = one client class; nothing here changes.
 *
 * The relay list is persisted as JSON so it survives restarts and is
 * pre-populated with common relays on first run.
 */
import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:math' show max;

import '../../util/nostr_event.dart';
import 'feed_quality.dart';
import 'firehose_curator.dart';
import 'nostr_local_client.dart';
import 'nostr_relay_client.dart';
import 'nostr_wire.dart';
import 'nostr_ws_client.dart';
import 'relay_event_store.dart';

/// How often we go BACK to the relays for new posts.
///
/// Not a freshness knob — a battery knob. The wss relays PUSH events over a live
/// subscription, so nothing here delays a post from a relay that is connected;
/// this governs the polls we make ourselves (the Reticulum relay re-query, and
/// the discovery-feed fetch). Those used to run every 30s and every 3s
/// respectively, on a phone that is usually in a pocket with the screen off and
/// nobody reading the feed.
///
/// Each poll is preceded by an immediate first fetch, so a cold start still
/// fills the feed at once — the interval only governs how often we go back.
const Duration kNostrPollInterval = Duration(minutes: 10);

/// The slice of an event store the hub needs — put + query. `RelayEventStore`
/// satisfies it via [NostrStore.of]; tests use an in-memory fake so the hub is
/// exercisable without the sqlite native library.
abstract class NostrStore {
  bool put(NostrEvent e, {int tier});
  List<NostrEvent> query(NostrFilter f);

  // Persisted engagement — reaction receipts survive restarts so like/reply
  // tallies load instantly instead of crawling back over the network. The
  // defaults are no-ops so in-memory test fakes need not care.
  bool addReaction(String eventId, String pubkey) => false;
  List<String> reactionPubkeys(String eventId) => const [];
  List<String> replyIdsFor(String eventId) => const [];

  factory NostrStore.of(RelayEventStore s) = _RelayEventStoreAdapter;
}

class _RelayEventStoreAdapter implements NostrStore {
  final RelayEventStore store;
  _RelayEventStoreAdapter(this.store);
  @override
  bool put(NostrEvent e, {int tier = 2}) => store.put(e, tier: tier);
  @override
  List<NostrEvent> query(NostrFilter f) => store.query(f);
  @override
  bool addReaction(String eventId, String pubkey) =>
      store.addReaction(eventId, pubkey);
  @override
  List<String> reactionPubkeys(String eventId) =>
      store.reactionPubkeys(eventId);
  @override
  List<String> replyIdsFor(String eventId) => store.replyIdsFor(eventId);
}

/// Common public relays pre-populated on first run, plus the device itself.
const List<String> kDefaultNostrRelays = [
  'local', // this device (RelayEventStore, also served over RNS + wss)
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
  'wss://relay.primal.net',
  'wss://purplepag.es',
];

class NostrRelayEndpoint {
  final String uri;
  bool enabled;
  NostrRelayEndpoint(this.uri, {this.enabled = true});

  NostrTransport get transport => nostrTransportOf(uri);

  Map<String, dynamic> toJson() => {'uri': uri, 'enabled': enabled};
  factory NostrRelayEndpoint.fromJson(Map<String, dynamic> j) =>
      NostrRelayEndpoint('${j['uri']}', enabled: j['enabled'] != false);
}

class NostrRelayHub {
  final NostrStore store;
  final void Function(String msg)? log;

  /// Where to persist the relay list (JSON). Null = in-memory only (tests).
  final String? persistPath;

  /// Builds a client for an `rns://…` endpoint (aurora resolves the hash to an
  /// RnsIdentity + RelayNode). ws:// and local are built by the hub itself.
  final NostrRelayClient? Function(String uri)? rnsClientFactory;

  /// Called after any event is merged into the store — the device's own wss
  /// server hooks this to LIVE-push mesh/internet events to LAN subscribers.
  final void Function(NostrEvent event)? onStored;

  final Map<String, NostrRelayEndpoint> _endpoints = {};
  final Map<String, NostrRelayClient> _clients = {};

  // Per-subscription: the active filters, a bounded inbox the wapp drains, and a
  // seen-id set so the same event from several relays is delivered once.
  final Map<String, List<NostrFilter>> _subFilters = {};
  final Map<String, Queue<NostrEvent>> _inbox = {};
  final Map<String, Set<String>> _seen = {};
  static const int _maxInbox = 500;

  int _subSeq = 0;

  /// The relays this device is offered if it has never been offered them before.
  /// Injectable so a test can run the hub with no public relays (and therefore
  /// no real sockets).
  final List<String> defaultRelays;
  final Duration pollInterval;
  final Duration firehoseOpeningDelay;
  final Duration firehoseSettleDelay;

  /// A short beat after firing the (re)connects and before the REQ, so a fast
  /// handshake is ready. Kept separate from [firehoseSettleDelay] so a test can
  /// zero it out; in production the settle window does the real waiting anyway.
  final Duration firehoseConnectGrace;

  NostrRelayHub({
    required this.store,
    this.persistPath,
    this.rnsClientFactory,
    this.onStored,
    this.log,
    this.defaultRelays = kDefaultNostrRelays,
    this.pollInterval = kNostrPollInterval,
    this.firehoseOpeningDelay = const Duration(seconds: 12),
    this.firehoseSettleDelay = const Duration(seconds: 20),
    this.firehoseConnectGrace = const Duration(seconds: 2),
  });

  // ── Relay list ────────────────────────────────────────────────────────────

  /// Load persisted relays, and offer any default this device has never been
  /// offered before.
  ///
  /// Seeding the defaults ONLY on first run is how a device ends up stranded: the
  /// persisted list shadows the constant forever, so a relay added to the
  /// defaults later never reaches an existing install, and a list whose relays
  /// have since died stays dead. A phone was found running on two relays — one
  /// unreachable, one that answers no firehose — with a feed sixteen hours old.
  ///
  /// A default the user has REMOVED is not re-added: [_offered] remembers every
  /// default this device has ever been given, so "never offered" and "offered
  /// and thrown away" are different things. Disabled stays disabled too.
  Future<void> init() async {
    final loaded = _load();
    for (final e in loaded) {
      _endpoints[e.uri] = e;
    }
    var added = 0;
    for (final u in defaultRelays) {
      if (_offered.contains(u)) continue; // offered before; user's call now
      _offered.add(u);
      if (_endpoints.containsKey(u)) continue;
      _endpoints[u] = NostrRelayEndpoint(u);
      added++;
    }
    if (added > 0 || loaded.isEmpty) {
      log?.call('relays: added $added default(s), ${_endpoints.length} total');
      _save();
    }
    for (final e in _endpoints.values) {
      _ensureClient(e.uri);
    }
  }

  /// Every default relay this device has ever been offered (persisted next to
  /// the list itself). Without it, "the user removed this one" is
  /// indistinguishable from "this one is new", and a merge would resurrect what
  /// the user threw away on every single start.
  final Set<String> _offered = {};

  List<NostrRelayEndpoint> _load() {
    final p = persistPath;
    if (p == null) return const [];
    try {
      final f = File(p);
      if (!f.existsSync()) return const [];
      final j = jsonDecode(f.readAsStringSync());
      // Two shapes: the original bare list, and the current object that also
      // carries which defaults this device has already been offered. An old
      // file simply has no memory of what it was offered — every relay in it
      // counts as offered, so an upgrade adds the defaults it never had and
      // resurrects nothing.
      final List<dynamic> list;
      if (j is List) {
        list = j;
        for (final e in list) {
          if (e is Map && e['uri'] != null) _offered.add('${e['uri']}');
        }
      } else if (j is Map && j['relays'] is List) {
        list = j['relays'] as List;
        for (final u in (j['offered'] as List? ?? const [])) {
          _offered.add('$u');
        }
      } else {
        return const [];
      }
      return [
        for (final e in list)
          if (e is Map)
            NostrRelayEndpoint.fromJson(e.map((k, v) => MapEntry('$k', v))),
      ];
    } catch (e) {
      log?.call('relay list load failed: $e');
      return const [];
    }
  }

  void _save() {
    final p = persistPath;
    if (p == null) return;
    try {
      File(p).writeAsStringSync(
        jsonEncode({
          'relays': [for (final e in _endpoints.values) e.toJson()],
          'offered': _offered.toList(),
        }),
      );
    } catch (e) {
      log?.call('relay list save failed: $e');
    }
  }

  /// Relay list + live status for the UI panel.
  /// When a relay last delivered a frame, epoch ms. 0 = never.
  ///
  /// The engine paces itself on THIS, not on socket status. "A relay is
  /// connected" turned out to be useless as a signal: the app hosts its own
  /// LOCAL relay, which is always connected and always silent, so a phone with
  /// no network at all still looked busy and the engine kept its 400ms tick —
  /// draining subscriptions nothing was filling and re-running a whole-table
  /// sqlite join, at 98% of a core.
  ///
  /// Traffic is the honest signal: if nothing has arrived from any relay, there
  /// is nothing new to drain, whatever the sockets claim.
  int lastRelayFrameMs = 0;

  /// True when some relay has delivered a frame within [within].
  bool relayTrafficSince(Duration within) =>
      lastRelayFrameMs != 0 &&
      DateTime.now().millisecondsSinceEpoch - lastRelayFrameMs <=
          within.inMilliseconds;

  List<Map<String, dynamic>> relaysJson() => [
    for (final e in _endpoints.values)
      {
        'uri': e.uri,
        'scheme': e.transport.name,
        'enabled': e.enabled,
        'status':
            (_clients[e.uri]?.status ?? NostrRelayStatus.disconnected).name,
      },
  ];

  /// Turn a relay on or off without forgetting it. Off means: no subscriptions,
  /// no publishes, no connection — but it stays in the list, so a relay that is
  /// down (or that you simply do not want to talk to right now) does not have to
  /// be re-typed later.
  bool setRelayEnabled(String uri, bool enabled) {
    final e = _endpoints[uri];
    if (e == null || e.enabled == enabled) return false;
    e.enabled = enabled;
    _save();
    if (enabled) {
      final c = _ensureClient(uri);
      for (final f in _subFilters.entries) {
        c?.subscribe(f.key, f.value);
      }
    } else {
      final c = _clients.remove(uri);
      // ignore: discarded_futures
      c?.close();
    }
    return true;
  }

  /// Add a relay by URI. Returns false if the scheme is unknown or duplicate.
  bool addRelay(String uri) {
    final u = uri.trim();
    if (u.isEmpty || nostrTransportOf(u) == NostrTransport.unknown) {
      return false;
    }
    if (_endpoints.containsKey(u)) return false;
    _endpoints[u] = NostrRelayEndpoint(u);
    _save();
    final c = _ensureClient(u);
    // Backfill the new relay with every live subscription.
    if (c != null) {
      for (final e in _subFilters.entries) {
        c.subscribe(e.key, e.value);
      }
    }
    return true;
  }

  bool removeRelay(String uri) {
    final e = _endpoints.remove(uri);
    if (e == null) return false;
    _save();
    // ignore: discarded_futures
    _clients.remove(uri)?.close();
    return true;
  }

  NostrRelayClient? _ensureClient(String uri) {
    final existing = _clients[uri];
    if (existing != null) return existing;
    final NostrRelayClient? c;
    switch (nostrTransportOf(uri)) {
      case NostrTransport.local:
        c = NostrLocalClient(store, uri: uri);
      case NostrTransport.websocket:
        c = NostrWsClient(uri, log: log);
      case NostrTransport.reticulum:
        c = rnsClientFactory?.call(uri);
      case NostrTransport.unknown:
        c = null;
    }
    if (c == null) return null;
    c.onEvent = _onEvent;
    // EOSE = "that's my backlog". Recording it is what lets us tell "streaming me
    // new posts" from "read its cache back to me and went dead" — the two look
    // identical otherwise, and the watchdog believed the second was the first.
    c.onEose = (subId) {
      if (subId == _fireSub) {
        _fireEoseMs = DateTime.now().millisecondsSinceEpoch;
      }
    };
    c.onStatus = (_) {};
    // A refused subscription is not an error anywhere else in the stack: the
    // socket stays up and the events simply never come. Name it.
    c.onClosed = (subId, message) =>
        log?.call('relay $uri refused $subId: $message');
    _clients[uri] = c;
    // ignore: discarded_futures
    c.connect();
    return c;
  }

  // ── Subscribe / publish ────────────────────────────────────────────────────

  /// Open a subscription across every enabled relay. Returns a subId the wapp
  /// uses to [drainEvents]. Also answers immediately from the local store.
  String subscribe(List<NostrFilter> filters) =>
      subscribeWithId('h${_subSeq++}', filters);

  /// As [subscribe] but with a caller-supplied id (the off-isolate engine mints
  /// ids on the main side and passes them through).
  String subscribeWithId(String subId, List<NostrFilter> filters) {
    _subFilters[subId] = filters;
    _inbox[subId] = Queue<NostrEvent>();
    _seen[subId] = <String>{};
    for (final e in _endpoints.values) {
      if (!e.enabled) continue;
      _clients[e.uri]?.subscribe(subId, filters);
    }
    return subId;
  }

  void unsubscribe(String subId) {
    _subFilters.remove(subId);
    _inbox.remove(subId);
    _seen.remove(subId);
    _fireBatchMeta.remove(subId);
    for (final c in _clients.values) {
      c.unsubscribe(subId);
    }

    // A discovery subscriber leaving must not leave the machinery pointing at a
    // dead inbox. This is what made pull-to-refresh (unsubscribe → re-subscribe)
    // kill the discovery feed for the life of the process: _discoFeedSub still
    // named the id we had just deleted, so every qualifying post was buffered
    // into nothing and the re-subscribe was handed the same corpse.
    if (_discoSubscribers.remove(subId) && _discoSubscribers.isEmpty) {
      _teardownDiscovery();
    }
    if (_fireSubscribers.remove(subId)) {
      log?.call(
        'firehose: unsubscribe $subId, ${_fireSubscribers.length} remain',
      );
      if (_fireSubscribers.isEmpty) {
        // GRACE, not instant teardown. A wapp rebuild unsubscribes then
        // re-subscribes within a frame; tearing down in that gap cancels the
        // in-flight edition and re-arms the deadline ten minutes out, so the
        // feed froze under ordinary use. Only truly leaving (no resubscribe
        // within the grace) tears the machinery down.
        _fireTeardownTimer?.cancel();
        _fireTeardownTimer = Timer(const Duration(seconds: 6), () {
          _fireTeardownTimer = null;
          if (_fireSubscribers.isEmpty) _teardownFirehose();
        });
      }
    }
  }

  Timer? _fireTeardownTimer;

  void _teardownDiscovery() {
    _discoFeedSub = null;
    final react = _discoReactSub;
    _discoReactSub = null;
    if (react != null) {
      _subFilters.remove(react);
      _inbox.remove(react);
      _seen.remove(react);
      for (final c in _clients.values) {
        c.unsubscribe(react);
      }
    }
    _discoTimer?.cancel();
    _discoTimer = null;
    _discoPrime?.cancel();
    _discoPrime = null;
    _discoPrimed = false;
  }

  // ── Discovery feed (for users who follow nobody) ────────────────────────────
  // A raw kind-1 firehose is mostly spam/repeats. Instead we watch the kind-7
  // REACTION firehose, tally distinct likers per event, and only surface a post
  // once it has crossed a like threshold — then fetch that specific note by id.
  // Spam gets no reactions, so it never appears.
  String? _discoFeedSub; // the internal feed the qualifying posts land in
  String? _discoReactSub; // internal kind-7 subscription

  /// Everyone drinking from the discovery feed.
  ///
  /// There is more than one: the launcher hero subscribes at startup and the
  /// Social wapp subscribes when it opens. The old code returned the FIRST
  /// subscriber's id to everybody and never created an inbox for the others, so
  /// the second subscriber drained an id the hub would never fill — silently,
  /// forever. Whoever asked second simply got no feed.
  final Set<String> _discoSubscribers = {};
  int _discoMinLikes = 2;
  final Map<String, Set<String>> _discoLikers = {}; // eventId → distinct likers
  final Set<String> _discoWanted = {}; // ids past the threshold
  final Set<String> _discoFetched = {}; // ids already requested
  final List<String> _discoToFetch = []; // newly wanted, awaiting a REQ
  Timer? _discoTimer;

  /// Ids of posts we count engagement for, and pubkeys we resolve profiles for
  /// (the off-isolate engine polls these to build its snapshots).
  Iterable<String> get trackedStatIds => _statTracked;
  Iterable<String> get trackedProfilePubs => _profTracked;

  /// Start (or return) the discovery feed: a subId that only receives kind-1
  /// posts which have gathered at least [minLikes] distinct reactions.
  String subscribeDiscovery({int minLikes = 2}) =>
      subscribeDiscoveryWithId('disco${_subSeq++}', minLikes: minLikes);

  String subscribeDiscoveryWithId(String feed, {int minLikes = 2}) {
    // EVERY subscriber gets its own inbox. Handing them all one shared id (what
    // this used to do) meant the second one drained a queue that did not exist.
    _discoSubscribers.add(feed);
    _inbox[feed] = Queue<NostrEvent>();
    _seen[feed] = <String>{};

    final existing = _discoFeedSub;
    if (existing != null) return feed; // machinery already running

    _discoMinLikes = minLikes;
    _discoFeedSub = feed;
    // Internal reactions subscription — tallied, never drained by the wapp.
    final react = 'discoR${_subSeq++}';
    _discoReactSub = react;
    final rf = [
      const NostrFilter(kinds: [7], limit: 500),
    ];
    _subFilters[react] = rf;
    _inbox[react] = Queue<NostrEvent>();
    _seen[react] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(react, rf);
    }
    // Fetch NOW so the feed fills immediately, then settle into a slow poll.
    //
    // This used to re-poll every 3 SECONDS. Nobody needs a discovery feed that
    // fresh: the phone is usually in a pocket with the screen off, and a poll
    // interval is a battery setting, not a freshness setting. Ten minutes.
    if (_discoTimer == null) {
      _discoFetch();
      _discoTimer = Timer.periodic(kNostrPollInterval, (_) => _discoFetch());
    }
    return feed;
  }

  // ── The live firehose (the "All" tab) ──────────────────────────────────────
  //
  // Discovery (above) can only ever surface a post that has ALREADY collected
  // likes — it watches reactions and then fetches the post by id. That makes it
  // a "popular" feed, and it is fine for that, but it was also being used as the
  // All tab, where it guarantees the newest thing on screen is an hour old.
  //
  // This is the actual firehose: a plain live kind-1 subscription that the
  // relays PUSH to us, sub-second. What makes it usable rather than a sewer is
  // the quality gate (feed_quality.dart) — and what makes the STRICT gate
  // possible is that we ask for kind-0 in the same breath, so the authors
  // posting right now are exactly the authors whose profiles arrive.

  String? _fireSub; // the internal relay subscription
  final Set<String> _fireSubscribers = {}; // ids the wapp/host drains
  FirehoseFilter? _fireFilter;

  /// Pubkeys we have a kind-0 for. An in-memory set, not a store query: the gate
  /// runs on EVERY firehose event, and a sqlite round-trip per post is exactly
  /// the kind of per-item work that turns the engine isolate into a hot core.
  /// Misses are memoized too — on a public firehose most authors are unknown,
  /// and a cache that only remembers hits re-queries them forever
  /// (aurora/docs/performance.md §3.2).
  final Set<String> _haveProfile = {};
  final Set<String> _noProfile = {};

  /// Self + everyone we follow: they bypass the gate entirely. Pushed in by the
  /// main isolate, which owns the authoritative follow set.
  Set<String> trustedAuthors = {};

  /// My own pubkey. Everything I write, and everything ANYONE writes ABOUT me,
  /// is kept in the local store at tier `self` — see [_isMine].
  String? selfPubkey;

  /// Authors the user muted.
  ///
  /// Matched on the **12-char author key** (the first 12 hex chars of the
  /// pubkey) as well as the full key, because that is what the feed shows on a
  /// post and therefore what the user is actually pointing at when they mute.
  /// Case-insensitive: the host keys upper, the wire is lower.
  ///
  /// A muted author is rejected by the gate BEFORE the post is stored. Muting is
  /// not a display filter — it is a refusal to carry.
  Set<String> mutedAuthors = {};

  bool _isMuted(String pub) {
    if (mutedAuthors.isEmpty) return false;
    final up = pub.toUpperCase();
    if (mutedAuthors.contains(up) || mutedAuthors.contains(pub)) return true;
    if (up.length < 12) return false;
    return mutedAuthors.contains(up.substring(0, 12));
  }

  String subscribeFirehose({bool requireProfile = true}) =>
      subscribeFirehoseWithId(
        'fire${_subSeq++}',
        requireProfile: requireProfile,
      );

  String subscribeFirehoseWithId(String subId, {bool requireProfile = true}) {
    _fireTeardownTimer?.cancel(); // a rebuild resubscribing — keep the machinery
    _fireTeardownTimer = null;
    _fireSubscribers.add(subId);
    _inbox[subId] = Queue<NostrEvent>();
    _seen[subId] = <String>{};
    _fireBatchMeta[subId] = <String, Map<String, dynamic>>{};
    _fireFilter ??= FirehoseFilter(requireProfile: requireProfile);

    // Ensure the always-on firehose machinery BEFORE the _fireSub early-out.
    //
    // The sweep, curate, profile-fetch and watchdog timers must run whenever ANY
    // subscriber exists — not only for whoever happened to arm _fireSub. They
    // used to be created only on the arming path, AFTER the `_fireSub != null`
    // return below. That left a lethal state: teardown (last subscriber gone)
    // cancels every timer but deliberately KEEPS _fireFilter with its held
    // posts; a poll's `finally` also nulls _fireSub without touching the timers;
    // so a subscriber arriving afterwards could take the early return and never
    // recreate the sweep. The gate then sat with posts held pending-profile and
    // NO sweep to release them — every consumer drained zero and the All feed
    // froze while held=N stayed constant. All four are ??= idempotent, so
    // calling this on every subscribe is free once armed.
    _ensureFirehoseMachinery();

    if (_fireSub != null) {
      // The launcher and Social hand the same firehose to each other. A second
      // subscriber used to miss the only opening timer and drain zero forever.
      _scheduleOpeningBatch(subId, _fireLifecycle);
      return subId;
    }

    final lifecycle = ++_fireLifecycle;
    _openFirehoseReq();
    _scheduleOpeningBatch(subId, lifecycle);
    return subId;
  }

  /// Create the firehose's always-on timers if they are not already running.
  /// Idempotent (every timer is `??=`), so it is safe to call on every
  /// subscribe. See [subscribeFirehoseWithId] for why this must not live behind
  /// the `_fireSub` arming check.
  void _ensureFirehoseMachinery() {
    // Watchdog. A relay caps how many subscriptions one connection may hold and
    // silently drops the excess — and we hold a lot of them (profiles, stats,
    // reactions, web-of-trust, search…), several of which churn their ids. The
    // firehose was observed going quiet after its first burst for exactly this
    // reason: nobody had closed it, the relay had just stopped answering it.
    // There is no error to catch, so the only honest signal is silence.
    // THE WATCHDOG DOES NOT CHURN THE SUBSCRIPTION.
    //
    // It used to CLOSE and re-REQ the firehose every 60 seconds of silence, and
    // that is what killed it. The evidence is on the device: the discovery
    // subscription (kind-7, opened once, never touched again) streams events
    // continuously down the very same socket, while the firehose — the one we
    // kept re-asking for — went silent after its first burst. A relay will drop a
    // subscription that is torn down and re-issued on a loop, and no CLOSED frame
    // is ever sent to tell you so.
    //
    // So: a live subscription is left ALONE. It is re-issued exactly once per
    // connection, by the client, on reconnect. If the socket itself is dead the
    // idle watchdog (nostr_ws_client) notices — the kind-7 traffic proves whether
    // frames are flowing at all — and a reconnect replays every subscription we
    // hold, firehose included.
    //
    // What stays here is the DIAGNOSIS: say out loud that the firehose is quiet,
    // and whether the relay ended its backlog and then never pushed again.
    _fireWatchdog ??= Timer.periodic(const Duration(seconds: 30), (_) {
      if (_fireSub == null) return;
      final now = DateTime.now().millisecondsSinceEpoch;
      if (now - _fireLastEventMs < _fireSilenceMs) return;
      final live = [
        for (final e in _endpoints.values)
          if (e.enabled &&
              _clients[e.uri]?.status == NostrRelayStatus.connected)
            e.uri,
      ];
      _fireSilentRounds++;
      final eosed = _fireEoseMs > 0 && _fireEoseMs >= _fireLastEventMs;
      log?.call(
        'firehose: no new events for '
        '${(now - _fireLastEventMs) ~/ 1000}s '
        '(connected: ${live.isEmpty ? "NONE" : live.join(", ")}'
        '${eosed ? ", backlog ended" : ""})',
      );

      // Only a genuinely dead relay gets cycled, and only after a long silence —
      // never as a reflex. Cycling is a big hammer: it drops the subscriptions
      // that ARE working (discovery, follows, profiles) along with the one that
      // is not.
      if (_fireSilentRounds >= 6) {
        _fireSilentRounds = 0;
        log?.call(
          'firehose: ${_fireSilenceMs * 6 ~/ 1000}s without a single new '
          'event — cycling sockets',
        );
        for (final uri in live) {
          _clients[uri]?.reconnect();
        }
      }
    });

    // Ask for the held authors' profiles in one small batch, slowly. This is a
    // background chore, not a hot path: the posts are already held, and a REQ
    // storm is what got us dropped by the relays in the first place.
    _fireProfTimer ??= Timer.periodic(
      const Duration(seconds: 10),
      (_) => _firehoseProfileFetch(),
    );

    // Show what the relays would not name. A held post whose kind-0 never comes
    // is DELIVERED once its hold expires — with a short-npub identity, which the
    // UI renders perfectly well. It used to be destroyed in silence, and on a
    // network where the relays are stingy with kind-0 that meant an empty All
    // tab and a pending queue frozen at 42 for twenty minutes.
    // THE FEED IS A POLL, NOT A STREAM. Every 10 minutes, while somebody is
    // actually looking (subscribers exist): re-ask the firehose REQ — the
    // `since` watermark makes it one cheap window, and a fresh REQ reliably
    // returns the newest posts where waiting for live push on a phone does not —
    // give the relays ~20s to answer and the gate + curator to rank, then hand
    // the feed the best of the batch, newest-first.
    // Network collection needs [firehoseSettleDelay] before a batch can be
    // handed over. Start each collection early enough that commits, rather
    // than requests, remain on the advertised [pollInterval] cadence.
    //
    // ARM ONLY IF NOTHING IS ARMED. A new "first subscriber" appears on every
    // tab toggle (All -> Following -> All) and page rebuild, and re-arming the
    // deadline each time pushed the first automatic edition ten minutes into
    // the future again and again — a user merely USING the app could keep the
    // deadline permanently out of reach. The schedule belongs to the wall
    // clock, not to the subscriber's lifecycle.
    if (_nextAutomaticAtMs == 0) {
      _nextAutomaticAtMs =
          DateTime.now().millisecondsSinceEpoch +
          max(
            0,
            pollInterval.inMilliseconds - firehoseSettleDelay.inMilliseconds,
          );
    }
    _curateTimer ??= Timer.periodic(
      const Duration(seconds: 30),
      (_) => backgroundTick(),
    );

    _fireSweepTimer ??= Timer.periodic(const Duration(seconds: 15), (_) {
      final f = _fireFilter;
      if (f == null) {
        log?.call('firehose sweep: no filter');
        return;
      }
      final ripe = f.sweepExpired(DateTime.now().millisecondsSinceEpoch);
      if (ripe.isNotEmpty || f.pendingNow > 0) {
        final age =
            f.oldestHoldAgeMs(DateTime.now().millisecondsSinceEpoch) ~/ 1000;
        log?.call(
          'firehose sweep: ripe=${ripe.length} still-held=${f.pendingNow} '
          'oldest=${age}s subscribers=${_fireSubscribers.length}',
        );
      }
      for (final e in ripe) {
        fireReleased++;
        if (store.put(e)) {
          eventsStored++;
          onStored?.call(e);
        }
        _curator.offer(
          e,
          _signalsFor(e),
          DateTime.now().millisecondsSinceEpoch,
        );
      }
    });
  }

  Timer? _fireWatchdog;
  int _fireLastEventMs = 0;
  int _fireSilentRounds = 0;

  // Every firehose event id we have already gated. Bounded, evicted oldest-first
  // — NEVER cleared wholesale, or the next backlog looks new again.
  final Set<String> _fireSeenIds = {};
  static const int _fireSeenMax = 4000;

  // The newest created_at we have accepted. The next REQ asks for `since` this,
  // so a re-open costs one round trip instead of 200 stale events per relay.
  int _fireNewestSec = 0;
  int _fireOldestSec = 0;
  int? _fireBackfillUntilSec;
  int _fireEoseMs = 0;

  // What actually happened, per window: new events vs redeliveries. Without this
  // split, "seen=200 kept=0" is unreadable — is the gate eating it, or is the
  // relay reading its cache back to us? Those have opposite fixes.
  int fireNew = 0;
  int fireDup = 0;
  int fireReleased = 0;

  // Authors we have ASKED about and are still waiting on: pubkey -> attempts.
  // Asking once and forgetting (which is what the old code did — it removed the
  // author from the queue the moment the REQ went out) means a relay that drops
  // the REQ, or answers it after our one-shot sub was reaped, costs that author
  // their name forever, and every post of theirs is held and then destroyed.
  final Map<String, int> _profileAsked = {};
  static const int _profileMaxAttempts = 3;
  static const int _fireSilenceMs = 60 * 1000;

  // Authors whose posts are held pending a profile. Fetched in ONE small REQ on
  // a slow timer — see the note in the FeedPending branch for why this is not
  // trackProfile.
  final Set<String> _profileWanted = {};
  final Map<String, int> _fireProfSubs = {}; // one-shot REQ subs → created ms
  Timer? _fireProfTimer;
  Timer? _fireSweepTimer;
  static const int _fireProfBatch = 100;
  static const int _fireProfTtlMs = 30 * 1000;

  void _firehoseProfileFetch() {
    // Reap the one-shot REQs: their answers arrived long ago, or are not coming,
    // and an open filter taxes every future event the relay sends us.
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    for (final sub in [
      for (final e in _fireProfSubs.entries)
        if (nowMs - e.value > _fireProfTtlMs) e.key,
    ]) {
      _fireProfSubs.remove(sub);
      _subFilters.remove(sub);
      _inbox.remove(sub);
      _seen.remove(sub);
      for (final e in _endpoints.values) {
        _clients[e.uri]?.unsubscribe(sub);
      }
    }

    if (_profileWanted.isEmpty) return;
    final batch = <String>[];
    for (final p in _profileWanted) {
      if (_haveProfile.contains(p)) continue;
      if ((_profileAsked[p] ?? 0) >= _profileMaxAttempts) continue;
      batch.add(p);
      if (batch.length >= _fireProfBatch) break;
    }
    // An author stays in the queue until their kind-0 actually ARRIVES (see
    // _releaseProfile) or we have asked _profileMaxAttempts times. Removing them
    // the moment the REQ went out — which is what this did — meant a dropped or
    // late-answered REQ cost that author their name permanently, and every post
    // of theirs was held for three minutes and then thrown away.
    for (final p in batch) {
      _profileAsked[p] = (_profileAsked[p] ?? 0) + 1;
      if (_profileAsked[p]! >= _profileMaxAttempts) {
        _profileWanted.remove(
          p,
        ); // asked enough; the hold TTL will show it anyway
      }
    }
    if (_profileAsked.length > 4000) {
      _profileAsked.remove(_profileAsked.keys.first);
    }
    if (batch.isEmpty) return;

    final sub = 'fireP${_subSeq++}';
    final f = [
      NostrFilter(kinds: const [0], authors: batch),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    _fireProfSubs[sub] = nowMs;
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  void _openFirehoseReq({int? until}) {
    final sub = 'fireR${_subSeq++}';
    _fireSub = sub;
    _fireLastEventMs = DateTime.now().millisecondsSinceEpoch;
    // kind-0 rides along with kind-1 on purpose — see above.
    //
    // `since` is what makes a re-open cheap. Without it every relay replayed its
    // most recent 200 events at us on every single re-open, forever — the
    // backlog that inflated the flood rule and kept the watchdog convinced the
    // feed was alive. A small overlap (60s) covers clock skew between relays.
    final nowSec = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final recentFloor = nowSec - kNostrPollInterval.inSeconds;
    // An automatic refresh is specifically the current ten-minute edition.
    // On a cold start, an unbounded `limit` query can contain hours of relay
    // backlog and keep the isolate ranking stale notes while the UI waits. Keep
    // a one-minute watermark overlap, but never ask earlier than this edition.
    // Manual requests pass [until] and deliberately remain backward-looking.
    final validNewest = _fireNewestSec <= nowSec + 60 ? _fireNewestSec : 0;
    final since = until == null
        ? (validNewest > 0 ? max(validNewest - 60, recentFloor) : recentFloor)
        : null;
    log?.call('firehose: REQ $sub since=$since until=$until');
    final f = [
      NostrFilter(kinds: const [0, 1], limit: 100, since: since, until: until),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  void _scheduleOpeningBatch(String subId, int lifecycle) {
    Timer(firehoseOpeningDelay, () {
      if (!_fireSubscribers.contains(subId) || lifecycle != _fireLifecycle) {
        log?.call(
          'curator: opening timer cancelled for $subId '
          '(present=${_fireSubscribers.contains(subId)}, '
          'lifecycle=$lifecycle/$_fireLifecycle)',
        );
        return;
      }
      log?.call('curator: opening timer fired for $subId');
      // Relay sockets may still be connecting when the opening timer fires.
      // Re-ask and allow the same settle window as scheduled/manual refresh;
      // taking the buffer once and returning zero left this subscriber empty
      // forever when connection setup completed a moment later.
      unawaited(_requestFirehoseBatch(n: 100, mode: 'opening'));
    });
  }

  /// Hand the feed whatever the curator is holding, now. The timer does this on
  /// its own cadence; a test should not have to wait ten seconds to see a post.
  int debugCurateNow() {
    final out = _curator.take(DateTime.now().millisecondsSinceEpoch);
    for (final e in out) {
      curatorDelivered++;
      _deliverFirehose(e);
    }
    return out.length;
  }

  /// What the silence watchdog does, exposed so a test can prove a re-open asks
  /// for what is NEW rather than dragging the same backlog back.
  void debugReopenFirehose() {
    _closeFirehoseReq();
    _openFirehoseReq();
  }

  void _closeFirehoseReq() {
    final sub = _fireSub;
    _fireSub = null;
    if (sub == null) return;
    _subFilters.remove(sub);
    _inbox.remove(sub);
    _seen.remove(sub);
    for (final e in _endpoints.values) {
      _clients[e.uri]?.unsubscribe(sub);
    }
  }

  void _teardownFirehose() {
    _fireTeardownTimer?.cancel();
    _fireTeardownTimer = null;
    _fireLifecycle++;
    _fireWatchdog?.cancel();
    _fireWatchdog = null;
    _fireProfTimer?.cancel();
    _fireProfTimer = null;
    _fireSweepTimer?.cancel();
    _fireSweepTimer = null;
    _curateTimer?.cancel();
    _curateTimer = null;
    _fireBatchInFlight = false;
    // The DEADLINE SURVIVES teardown. Closing Social only means nobody is
    // looking right now; when the tab reopens (often seconds later) the next
    // edition must still be where the clock left it, not ten minutes away.
    // The REQ stops; the KNOWLEDGE stays. Nulling the filter here threw away
    // every held post and every author we were still waiting on a name for —
    // on every page close — so re-opening Social always started from nothing and
    // replayed the whole cold-start stall. The gate's caches are bounded; they
    // cost nothing to keep, and keeping them is what makes a re-open instant.
    _closeFirehoseReq();
  }

  bool _hasProfile(String pub) {
    if (_haveProfile.contains(pub)) return true;
    if (_noProfile.contains(pub)) return false;
    final known = profileOf(pub) != null;
    (known ? _haveProfile : _noProfile).add(pub);
    // Bound the miss set: a firehose meets an endless supply of strangers.
    if (_noProfile.length > 20000) _noProfile.clear();
    return known;
  }

  /// One firehose event. Returns true if it was handled here (so [_onEvent]
  /// stops), false to fall through to the normal path.
  /// Events that actually reached the firehose. Without this, an empty feed is
  /// ambiguous: is the gate eating everything, or is the relay sending nothing?
  /// Those have completely different fixes, and guessing wastes a build cycle.
  int fireSeen = 0;

  bool _onFirehose(NostrEvent event, int nowMs) {
    fireSeen++;

    // ── The SAME event is not news, however many times it is handed to us ──
    //
    // Every relay answers a REQ with its recent window, and the watchdog used to
    // mint a fresh subscription id every 60 seconds — so the same 200 posts came
    // back, from four relays, over and over. Nothing here deduped them: the
    // firehose path returns before `_bufferForSub`/`_seen`, and the gate never
    // looks at an event id. The consequences were all three of the symptoms:
    //
    //   * the flood rule counted DELIVERIES, so one honest author redelivered by
    //     four relays looked like a spammer and their real posts were rejected —
    //     adding a relay made the feed emptier;
    //   * the watchdog treated that stale burst as proof of life, so it could
    //     never escalate and the socket was never cycled;
    //   * and the whole cycle repeated for twenty minutes while the log happily
    //     reported four connected relays.
    //
    // An event id is a content hash. Seen once, seen forever.
    final id = event.id;
    if (id != null) {
      if (!_fireSeenIds.add(id)) {
        fireDup++;
        return true; // a redelivery: not new, not news, not proof of anything
      }
      while (_fireSeenIds.length > _fireSeenMax) {
        _fireSeenIds.remove(
          _fireSeenIds.first,
        ); // oldest out, never a wholesale clear
      }
    }

    // Proof of life means a NEW event. Anything else is the relay reading its
    // cache back to us.
    _fireLastEventMs = nowMs;
    _fireSilentRounds = 0;
    fireNew++;

    // The watermark the next re-open asks from, so a reconnect does not drag the
    // same backlog back across the network.
    final nowSec = nowMs ~/ 1000;
    if (event.createdAt <= nowSec + 60 && event.createdAt > _fireNewestSec) {
      _fireNewestSec = event.createdAt;
    }
    if (event.kind == NostrEventKind.textNote &&
        (_fireOldestSec == 0 || event.createdAt < _fireOldestSec)) {
      _fireOldestSec = event.createdAt;
    }

    final filter = _fireFilter;
    if (filter == null) return true;

    // A profile: remember it, keep it (the UI needs the name and picture), and
    // release whatever of that author's posts was waiting on exactly this.
    if (event.kind == NostrEventKind.setMetadata) {
      _releaseProfile(event, nowMs);
      return true;
    }

    if (event.kind != NostrEventKind.textNote) return true;

    final verdict = filter.verdict(
      event,
      hasProfile: _hasProfile,
      trusted: trustedAuthors.contains,
      muted: _isMuted,
      nowMs: nowMs,
    );
    switch (verdict) {
      case FeedKeep():
        // The gate said yes — NOW it is worth cryptography. Rejected events
        // (most of the firehose) never reach a verify at all.
        if (!_verify(event)) return true;
        // Store only what we would show. Persisting the whole public firehose
        // would be an INSERT per junk post on the engine isolate, forever.
        if (store.put(event)) {
          eventsStored++;
          onStored?.call(event);
        }
        // Somebody the user FOLLOWS is not a candidate to be ranked against
        // strangers — they are the point. Straight through.
        if (trustedAuthors.contains(event.pubkey)) {
          _deliverFirehose(event);
        } else {
          // Everyone else is a candidate. The curator decides what is worth the
          // user's attention and at what rate — a firehose is not a feed, and
          // pouring 150 events a second at a wapp that can take 26 is how the
          // top of the feed ended up minutes old and getting older.
          _curator.offer(event, _signalsFor(event), nowMs);
          _authorAccepted[event.pubkey] =
              (_authorAccepted[event.pubkey] ?? 0) + 1;
          if (_authorAccepted.length > 4000) {
            _authorAccepted.remove(_authorAccepted.keys.first);
          }
        }
      case FeedPending():
        // Hold it, and QUEUE the author for a profile lookup.
        //
        // Deliberately NOT trackProfile(): that one re-issues a single REQ
        // carrying up to 500 authors every time it is called, and a firehose
        // introduces a new stranger every second or two. The resulting REQ storm
        // got our subscriptions dropped by the relays — including the firehose
        // itself, which then went silent while the profiles it was waiting for
        // never arrived. The feed strangled itself.
        //
        // [_profileWanted] instead accumulates authors and asks for them in one
        // small batch on a slow timer (see [_firehoseProfileFetch]).
        if (!_verify(event)) return true; // held posts are delivered later
        filter.hold(event, nowMs);
        if (_profileWanted.length < 2000) _profileWanted.add(event.pubkey);
      case FeedReject():
        break; // counted in the filter's stats; never stored, never shown
    }
    return true;
  }

  /// A kind-0 arrived — from ANY subscription. Remember it, store it, and hand
  /// back every post of that author's that was waiting to learn their name.
  void _releaseProfile(NostrEvent event, int nowMs) {
    if (!_verify(event)) return; // a forged profile names nobody
    _haveProfile.add(event.pubkey);
    _noProfile.remove(event.pubkey);
    _profileWanted.remove(event.pubkey);
    _profileAsked.remove(event.pubkey); // answered: stop retrying
    if (store.put(event)) {
      eventsStored++;
      onStored?.call(event);
    }
    final filter = _fireFilter;
    if (filter == null) return;
    for (final held in filter.release(event.pubkey, nowMs)) {
      fireReleased++;
      if (store.put(held)) {
        eventsStored++;
        onStored?.call(held);
      }
      _curator.offer(held, _signalsFor(held), nowMs);
      _authorAccepted[held.pubkey] = (_authorAccepted[held.pubkey] ?? 0) + 1;
    }
  }

  final FirehoseCurator _curator = FirehoseCurator();
  final Map<String, int> _authorAccepted = {};
  Timer? _curateTimer;
  int _nextAutomaticAtMs = 0;
  int _fireBatchSeq = 0;
  bool _fireBatchInFlight = false;
  int _fireLifecycle = 0;

  // Per subscriber/event metadata is attached only when the event leaves the
  // engine isolate. NostrEvent remains protocol-pure and signature-safe.
  final Map<String, Map<String, Map<String, dynamic>>> _fireBatchMeta = {};

  /// What this device already knows about a candidate post. No network calls:
  /// every one of these is a cache we filled on the way here.
  CandidateSignals _signalsFor(NostrEvent e) {
    final id = e.id ?? '';
    return (
      likes: _statReact[id]?.length ?? 0,
      replies: _statReply[id]?.length ?? 0,
      hasMedia: _hasMedia(e),
      authorHasProfile: _haveProfile.contains(e.pubkey),
      authorSeenBefore: _authorAccepted[e.pubkey] ?? 0,
    );
  }

  static bool _hasMedia(NostrEvent e) {
    for (final t in e.tags) {
      if (t.isNotEmpty && t[0] == 'imeta') return true;
    }
    final c = e.content.toLowerCase();
    return c.contains('.jpg') ||
        c.contains('.jpeg') ||
        c.contains('.png') ||
        c.contains('.gif') ||
        c.contains('.webp') ||
        c.contains('.mp4');
  }

  /// How many posts are ranked and waiting for their turn.
  int get curatorPending => _curator.pending;
  int curatorDelivered = 0;

  void _deliverFirehose(NostrEvent event) {
    // A post we are about to SHOW is a post whose likes and replies the user is
    // about to look at. Track it as it goes out — otherwise every card in the
    // feed reads "0 likes, 0 replies" no matter how popular the post is, which is
    // both wrong and exactly the signal the curator ranked it on.
    final id = event.id;
    if (id != null && id.length == 64) trackStats([id]);
    for (final sub in _fireSubscribers) {
      _bufferForSub(sub, event);
    }
  }

  void _deliverFirehoseBatch(List<NostrEvent> events, {required String mode}) {
    if (events.isEmpty) return;
    final generation = ++_fireBatchSeq;
    for (var index = 0; index < events.length; index++) {
      final event = events[index];
      final id = event.id;
      if (id == null) continue;
      for (final sub in _fireSubscribers) {
        _fireBatchMeta[sub]?[id] = {
          '_geogram_batch': generation,
          '_geogram_batch_mode': mode,
          '_geogram_batch_index': index,
          '_geogram_batch_size': events.length,
        };
      }
      curatorDelivered++;
      _deliverFirehose(event);
    }
  }

  Future<int> _requestFirehoseBatch({
    required int n,
    required String mode,
  }) async {
    if (_fireSubscribers.isEmpty) {
      log?.call('curator: $mode request skipped; no consumer');
      return 0;
    }
    if (_fireBatchInFlight) {
      log?.call('curator: $mode request ignored; batch already in flight');
      return 0;
    }
    _fireBatchInFlight = true;
    _fireBatchStartedMs = DateTime.now().millisecondsSinceEpoch;
    int? requestedUntil;
    log?.call(
      'curator: $mode request started, subscribers=${_fireSubscribers.length}',
    );
    try {
      // Re-ask on the EXISTING sockets — never reopen them here.
      //
      // On this device, opening a WebSocket inside the nostr-engine isolate
      // freezes the whole isolate (the synchronous part of WebSocketChannel.connect
      // blocks it; even fired unawaited it never yields). The device log caught it
      // exactly: an edition logged `step=connect` and never reached the line after
      // the reconnect, so every timer on the isolate stalled behind it and the feed
      // died. The sockets opened at engine startup DO work and keep delivering
      // (the same log shows seen=103), so an edition just closes and re-issues the
      // REQ on them with a fresh `since` window; a relay that cut us is recovered
      // by the client's own idle watchdog, not by reopening from here.
      log?.call('curator: $mode step=reask');
      if (mode == 'manual') {
        final until =
            _fireBackfillUntilSec ??
            (_fireOldestSec > 0
                ? _fireOldestSec - 1
                : DateTime.now().millisecondsSinceEpoch ~/ 1000);
        requestedUntil = until;
        _closeFirehoseReq();
        _openFirehoseReq(until: until);
      } else {
        _closeFirehoseReq();
        _openFirehoseReq();
      }
      log?.call('curator: $mode step=settle');
      await Future<void>.delayed(firehoseSettleDelay);
      log?.call('curator: $mode step=settled');
      if (_fireSubscribers.isEmpty) {
        log?.call('curator: $mode request cancelled; no consumer');
        return 0;
      }
      // NOTE: deliberately not aborting on a lifecycle bump. A wapp rebuild
      // churns the subscriber id mid-edition; as long as a consumer is present
      // the batch is still wanted, and aborting on churn is what made editions
      // never finish.
      if (mode == 'manual') {
        _fireBackfillUntilSec = _fireOldestSec > 0 ? _fireOldestSec - 1 : null;
        _closeFirehoseReq();
        _openFirehoseReq();
      }
      final out = _curator.takeBurst(n).toList(growable: true);
      if (mode == 'manual' && out.length < n && requestedUntil != null) {
        final have = {for (final event in out) event.id};
        final stored = store.query(
          NostrFilter(
            kinds: const [NostrEventKind.textNote],
            until: requestedUntil,
            limit: n * 3,
          ),
        );
        for (final event in stored) {
          if (out.length >= n) break;
          if (event.id == null || !have.add(event.id)) continue;
          out.add(event);
        }
        if (out.isNotEmpty) {
          var oldest = out.first.createdAt;
          for (final event in out.skip(1)) {
            if (event.createdAt < oldest) oldest = event.createdAt;
          }
          _fireBackfillUntilSec = oldest - 1;
        }
      }
      _deliverFirehoseBatch(out, mode: mode);
      final newest = out.fold<int>(
        0,
        (value, event) => event.createdAt > value ? event.createdAt : value,
      );
      final newestAge = newest == 0
          ? -1
          : DateTime.now().millisecondsSinceEpoch ~/ 1000 - newest;
      log?.call(
        'curator: $mode batch handed over ${out.length}, '
        '${_curator.pending} still ranked, newestAge=${newestAge}s',
      );
      return out.length;
    } catch (error, stack) {
      log?.call('curator: $mode request FAILED: $error\n$stack');
      return 0;
    } finally {
      _fireBatchInFlight = false;
      _lastEditionMs = DateTime.now().millisecondsSinceEpoch;
      // Close only the REQ, NOT the sockets. Disconnecting relays here re-opened
      // them on the next edition, which freezes the engine isolate on this device
      // (see step=reask above). The persistent sockets keep the feed alive.
      _closeFirehoseReq();
    }
  }

  /// One line per report: what each relay is ACTUALLY doing. Status alone lies —
  /// a socket can sit "connected" for twenty minutes and deliver nothing.
  String relayHealth() {
    final parts = <String>[];
    for (final e in _endpoints.values) {
      if (!e.enabled) continue;
      final c = _clients[e.uri];
      if (c == null) continue;
      final host = e.uri.replaceFirst('wss://', '');
      parts.add('$host=${c.status.name.substring(0, 4)}/${c.drainFrames()}');
    }
    return parts.join(' ');
  }

  /// The user is LOOKING NOW (app resumed, or pull-to-refresh). Recover every
  /// zombie socket immediately, and re-issue the firehose REQ once, bounded by
  /// the `since` watermark — one cheap fetch of whatever was missed while
  /// Android had the sockets frozen. This is not the churn loop that got the
  /// subscription dropped: it runs on a user gesture, not a timer.
  void resumeNetwork() {
    // Off-grid: sockets are assumed dead on resume. Rather than nurse the old
    // ones, bring the deadline forward so the next tick runs a fresh poll — the
    // edition reconnects everything from scratch anyway. Only if a consumer is
    // present and the last poll is genuinely stale, so foregrounding twice in a
    // row does not double-poll.
    if (_fireSubscribers.isEmpty) {
      log?.call('resume: no consumer');
      return;
    }
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now - _lastEditionMs > 60 * 1000) {
      _nextAutomaticAtMs = now; // due now → next backgroundTick refreshes
      log?.call('resume: last edition stale, refreshing');
      backgroundTick(nowMs: now);
    } else {
      log?.call('resume: last edition fresh, keeping');
    }
  }

  int _lastEditionMs = 0;

  /// Native Android and isolate timers both call this. The deadline is advanced
  /// before starting work, so concurrent heartbeats cannot duplicate a batch;
  /// an empty or failed batch also cannot kill the next ten-minute edition.
  int _bgTickN = 0;
  int _fireBatchStartedMs = 0;
  // Longer than a legitimate poll (fresh-connect + settle) but far shorter than
  // a wedge. A batch still running past this is dead and gets abandoned.
  static const int _fireBatchMaxMs = 90 * 1000;
  void backgroundTick({int? nowMs}) {
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    if ((_bgTickN++ % 30) == 0) {
      // Heartbeat proof-of-life + the guard state, so a silent scheduler is
      // never again a mystery. Throttled so it is not one line per 2s tick.
      log?.call('curator: tick subs=${_fireSubscribers.length} '
          'dueIn=${((_nextAutomaticAtMs - now) / 1000).round()}s '
          'inFlight=$_fireBatchInFlight');
    }
    if (_fireSubscribers.isEmpty) return; // no consumer, nothing to deliver to
    // A batch that never finished — the app was frozen mid-edition, a socket
    // hung, the isolate stalled — must NOT wedge every future edition. If it has
    // overstayed the hard cap, abandon it. Off-grid: assume anything in flight
    // for too long is dead.
    if (_fireBatchInFlight &&
        now - _fireBatchStartedMs > _fireBatchMaxMs) {
      log?.call('curator: abandoning a stuck batch '
          '(${((now - _fireBatchStartedMs) / 1000).round()}s in flight)');
      _fireBatchInFlight = false;
      _closeFirehoseReq(); // REQ only — reopening sockets freezes this isolate
    }
    if (now < _nextAutomaticAtMs) return;
    if (_fireBatchInFlight) return;
    if (_fireBatchInFlight) {
      log?.call('curator: deadline ignored; batch already in flight');
      return;
    }
    _nextAutomaticAtMs = now + pollInterval.inMilliseconds;
    log?.call('curator: automatic deadline fired; next in '
        '${pollInterval.inMinutes}m');
    unawaited(_requestFirehoseBatch(n: 100, mode: 'automatic'));
  }

  /// Resume the relay sockets and replace the foreground firehose batch once
  /// the relays have had time to answer. This is deliberately automatic, not
  /// the pull-to-refresh backfill path: returning from Android background must
  /// retain the current timeline until newer curated notes are ready.
  Future<int> resumeAndRefreshFirehose({int n = 100}) =>
      _requestFirehoseBatch(n: n, mode: 'automatic');

  /// A refresh: hand the feed the best [n] of what is ranked, right now.
  ///
  /// The user pulled the timeline down. That is a request for MORE, immediately —
  /// not for the next two posts on the ten-second timer.
  Future<int> refreshBurst({int n = 100}) async {
    // A tab change and a pull gesture can arrive in adjacent frames. Give the
    // wapp's activity_refresh command a short window to reopen its firehose
    // subscriber instead of completing with zero before that command runs.
    for (var i = 0; i < 50 && _fireSubscribers.isEmpty; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    return _requestFirehoseBatch(n: n, mode: 'manual');
  }

  /// Firehose accounting — what arrived, what was kept/held, and a count per
  /// drop reason. "The feed looks empty" must be answerable from the log.
  Map<String, int> drainFirehoseStats() {
    final f = _fireFilter;
    if (f == null) return const {};
    final seen = fireSeen;
    final fresh = fireNew;
    final dup = fireDup;
    final released = fireReleased;
    fireSeen = 0;
    fireNew = 0;
    fireDup = 0;
    fireReleased = 0;
    // `new` vs `dup` is the line that would have saved a day: "seen=200 kept=0"
    // is unreadable, but "seen=200 new=0 dup=200" says plainly that the relays
    // are reading their cache back to us and nothing is actually arriving.
    final delivered = curatorDelivered;
    curatorDelivered = 0;
    return {
      'seen': seen,
      'new': fresh,
      'dup': dup,
      'released': released,
      'held': _fireFilter?.pendingNow ?? 0,
      'shown': delivered, // what actually reached the feed
      'ranked': _curator.pending, // waiting their turn
      ...f.drainStats(),
    };
  }

  // Live discoF fetch subs → created-at ms. These are one-shot id fetches; the
  // relays answer within seconds. They used to be created every 3s and NEVER
  // unsubscribed — after hours the filter set grew unbounded and every inbound
  // event paid an O(subs) match against it (a measured hot engine isolate).
  final Map<String, int> _discoFetchSubs = {};
  static const int _discoFetchTtlMs = 30 * 1000;

  // The first fetch of a cold discovery feed.
  //
  // Discovery is two steps: tally kind-7 reactions, then REQ the posts that
  // qualified. The tally is empty when the feed is first subscribed, so the
  // fetch at subscribe time has nothing to ask for — and the next one is the
  // 10-minute poll. That left a fresh install staring at an empty hero for ten
  // minutes, which is precisely when it most needs something to show.
  //
  // So: once the reactions start qualifying posts, fetch them shortly after,
  // ONCE. The debounce lets a burst of reactions accumulate into a single REQ
  // rather than one per post, and after this the slow poll takes over — this is
  // not a return to the 3-second polling that used to peg the engine.
  Timer? _discoPrime;
  bool _discoPrimed = false;

  void _primeDiscovery() {
    if (_discoPrimed || _discoPrime != null) return;
    _discoPrime = Timer(const Duration(seconds: 5), () {
      _discoPrime = null;
      _discoPrimed = true;
      _discoFetch();
    });
  }

  void _discoFetch() {
    // Reap fetch subs past their TTL — their ids either arrived long ago or
    // aren't coming; keeping the filter only taxes every future event.
    if (_discoFetchSubs.isNotEmpty) {
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final expired = [
        for (final e in _discoFetchSubs.entries)
          if (nowMs - e.value > _discoFetchTtlMs) e.key,
      ];
      for (final sub in expired) {
        _discoFetchSubs.remove(sub);
        unsubscribe(sub);
      }
    }
    if (_discoToFetch.isEmpty) return;
    final batch = <String>[];
    while (_discoToFetch.isNotEmpty && batch.length < 100) {
      batch.add(_discoToFetch.removeAt(0));
    }
    final sub = 'discoF${_subSeq++}';
    final f = [
      NostrFilter(ids: batch, kinds: const [1]),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    _discoFetchSubs[sub] = DateTime.now().millisecondsSinceEpoch;
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  static String? _firstETag(NostrEvent e) {
    for (final t in e.tags) {
      if (t.length >= 2 && t[0] == 'e') return t[1];
    }
    return null;
  }

  /// Fold a reaction into the like tally; returns true if this was a reaction
  /// (so the caller skips normal store/buffer work for it).
  bool _discoTally(NostrEvent event) {
    if (_discoFeedSub == null || event.kind != NostrEventKind.reaction) {
      return false;
    }
    final liked = _firstETag(event);
    if (liked == null) return true;
    final likers = _discoLikers.putIfAbsent(liked, () => <String>{});
    likers.add(event.pubkey);
    if (likers.length >= _discoMinLikes && _discoFetched.add(liked)) {
      _discoWanted.add(liked);
      _discoToFetch.add(liked);
      _primeDiscovery();
      // Seed the on-screen like tally with the reactions that qualified this
      // post, so it shows its real count (>=2) immediately instead of 0.
      _statReact.putIfAbsent(liked, () => <String>{}).addAll(likers);
      if (!_statTracked.contains(liked)) {
        _statTracked.add(liked);
        _statReply.putIfAbsent(liked, () => <String>{});
      }
    }
    // Bound the tally map: forget the least-liked once it grows too large.
    if (_discoLikers.length > 8000) {
      final weak = _discoLikers.entries
          .where((e) => e.value.length < 2)
          .map((e) => e.key)
          .take(2000);
      for (final k in weak.toList()) {
        _discoLikers.remove(k);
      }
    }
    return true;
  }

  // ── Engagement stats (likes + replies per visible post) ─────────────────────
  final Map<String, Set<String>> _statReact = {}; // eventId → reactor pubkeys
  // NIP-25 says the reaction's CONTENT carries the verdict: "-" is a downvote,
  // anything else ("+", "🤙", an emoji) is a like. Tallying only "did someone
  // react" cannot tell an upvote from a downvote, so keep the two apart.
  final Map<String, Set<String>> _statUp = {}; // eventId → upvoter pubkeys
  final Map<String, Set<String>> _statDown = {}; // eventId → downvoter pubkeys
  final Map<String, Set<String>> _statReply = {}; // eventId → reply event ids
  final List<String> _statTracked = []; // rolling set of ids we count for
  String? _statSub;
  Timer? _statDebounce;

  /// Count reactions (kind-7) and replies (kind-1 with #e) for [ids] by
  /// subscribing to events that reference them. The feed calls this with the
  /// post ids currently on screen; a rolling window keeps the REQ bounded.
  void trackStats(List<String> ids) {
    var added = false;
    for (final id in ids) {
      if (id.length != 64 || _statReact.containsKey(id)) continue;
      _statTracked.add(id);
      // Seed from the store so counts are correct IMMEDIATELY (persisted
      // reaction receipts + already-stored kind-1 replies) instead of zero
      // until the relays redeliver. Live events then dedup into these sets.
      _statReact[id] = store.reactionPubkeys(id).toSet();
      _statReply[id] = store.replyIdsFor(id).toSet();
      _statUp[id] = <String>{};
      _statDown[id] = <String>{};
      added = true;
    }
    while (_statTracked.length > 300) {
      final old = _statTracked.removeAt(0);
      _statReact.remove(old);
      _statReply.remove(old);
      _statUp.remove(old);
      _statDown.remove(old);
    }
    if (added) {
      // Debounce: the feed adds ids in bursts as the user scrolls.
      _statDebounce?.cancel();
      _statDebounce = Timer(const Duration(milliseconds: 700), _statResub);
    }
  }

  void _statResub() {
    if (_statTracked.isEmpty) return;
    final prev = _statSub;
    if (prev != null) {
      _subFilters.remove(prev);
      _inbox.remove(prev);
      _seen.remove(prev);
      for (final c in _clients.values) {
        c.unsubscribe(prev);
      }
    }
    final ids = List<String>.from(_statTracked);
    final sub = 'stat${_subSeq++}';
    _statSub = sub;
    final f = [
      NostrFilter(kinds: const [7], tags: {'e': ids}),
      NostrFilter(kinds: const [1], tags: {'e': ids}),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  /// Record a reaction/reply against a tracked post. Returns true if it was an
  /// engagement event for a tracked post (so the caller skips normal handling).
  bool _tallyStats(NostrEvent event) {
    final ref = _firstETag(event);
    if (ref == null) return false;
    if (event.kind == NostrEventKind.reaction) {
      // NIP-25 puts the verdict in the content. Three DISJOINT buckets, so a
      // post is not counted twice: "+"/👍 is an upvote, "-"/👎 a downvote, and
      // any other emoji ("❤️", "🤙") is a plain like. Lumping them together
      // lit the heart and the thumb for the same single reaction.
      final c = event.content.trim();
      final isUp = c == '+' || c == '👍';
      final isDown = c == '-' || c == '👎';
      if (isUp) {
        _statUp[ref]?.add(event.pubkey);
        _statDown[ref]?.remove(event.pubkey);
        _statReact[ref]?.remove(event.pubkey);
      } else if (isDown) {
        _statDown[ref]?.add(event.pubkey);
        _statUp[ref]?.remove(event.pubkey);
        _statReact[ref]?.remove(event.pubkey);
      } else {
        _statReact[ref]?.add(event.pubkey);
      }
      return true; // reactions are never displayed
    }
    if (event.kind == NostrEventKind.textNote) {
      final s = _statReply[ref];
      if (s != null && event.id != null) s.add(event.id!);
      // a reply is still a note; let it flow on for storage/threading
    }
    return false;
  }

  /// (likes, replies, likedByMe) for a post id.
  (int, int, bool) statsOf(String id, String? selfPub) {
    final r = _statReact[id];
    final mine = selfPub != null && (r?.contains(selfPub) ?? false);
    return (r?.length ?? 0, _statReply[id]?.length ?? 0, mine);
  }

  /// (upvotes, downvotes, myVote) for a post id. myVote is 1, -1 or 0.
  (int, int, int) votesOf(String id, String? selfPub) {
    final up = _statUp[id];
    final down = _statDown[id];
    var mine = 0;
    if (selfPub != null) {
      if (up?.contains(selfPub) ?? false) {
        mine = 1;
      } else if (down?.contains(selfPub) ?? false) {
        mine = -1;
      }
    }
    return (up?.length ?? 0, down?.length ?? 0, mine);
  }

  /// Our own vote, recorded before it round-trips back from a relay.
  void recordVote(String id, String pub, int vote) {
    _statUp.putIfAbsent(id, () => <String>{});
    _statDown.putIfAbsent(id, () => <String>{});
    _statReact[id]?.remove(pub); // a vote is not also a like
    if (vote > 0) {
      _statUp[id]!.add(pub);
      _statDown[id]!.remove(pub);
    } else if (vote < 0) {
      _statDown[id]!.add(pub);
      _statUp[id]!.remove(pub);
    } else {
      _statUp[id]!.remove(pub);
      _statDown[id]!.remove(pub);
    }
  }

  /// Optimistically record our own like so the count updates before it round-
  /// trips back from a relay.
  void recordReaction(String id, String pub) {
    (_statReact[id] ??= <String>{}).add(pub);
    if (!_statTracked.contains(id)) _statTracked.add(id);
  }

  // ── Profiles (kind-0 metadata for post authors) ─────────────────────────────
  final List<String> _profTracked = []; // rolling set of author pubkeys
  final Set<String> _profSeen = {};
  String? _profSub;
  Timer? _profDebounce;

  bool _profDirty = false;

  /// Ensure we subscribe to (and thus store) the kind-0 profile for [pub]. Safe
  /// to call repeatedly; a rolling window keeps the REQ bounded.
  ///
  /// The timer here is a BATCH WINDOW, not a debounce, and the difference is the
  /// whole feature. It used to `cancel()` the pending timer on every new author
  /// — fine when authors trickled in from a feed you follow, fatal under a
  /// firehose: a new stranger every few hundred milliseconds reset the timer
  /// forever, so the profile REQ was never actually sent, and every post from a
  /// stranger sat waiting for a profile nobody had asked for. Let the first
  /// timer run; the authors that arrive meanwhile ride along in the same batch.
  void trackProfile(String pub) {
    if (pub.length != 64 || !_profSeen.add(pub)) return;
    _profTracked.add(pub);
    while (_profTracked.length > 500) {
      _profSeen.remove(_profTracked.removeAt(0));
    }
    _profDirty = true;
    if (_profDebounce != null) return; // a batch is already in flight
    _profDebounce = Timer(const Duration(seconds: 2), () {
      _profDebounce = null;
      if (!_profDirty) return;
      _profDirty = false;
      _profResub();
    });
  }

  /// Never re-subscribe more often than this. The 2s timer below is a batch
  /// window, which is right when authors trickle in — but a firehose supplies a
  /// new stranger every few hundred milliseconds, so the window closed and
  /// reopened forever: a fresh kind-0 REQ across every relay every two seconds,
  /// each one producing more inbound events. The first batch still goes out
  /// promptly; only the repeats are paced.
  static const Duration _profResubMinGap = Duration(seconds: 20);
  DateTime? _lastProfResub;
  Timer? _profResubPending;

  void _profResub() {
    if (_profTracked.isEmpty) return;
    final now = DateTime.now();
    final last = _lastProfResub;
    if (last != null) {
      final since = now.difference(last);
      if (since < _profResubMinGap) {
        // Do it when the gap is up, once, rather than dropping it.
        _profResubPending ??= Timer(_profResubMinGap - since, () {
          _profResubPending = null;
          _profResub();
        });
        return;
      }
    }
    _lastProfResub = now;
    // Re-subscribe kind-0 for ALL tracked authors. The persistent store already
    // avoids cross-session re-download (profileOf reads it); re-subscribing here
    // keeps retrying authors whose kind-0 hasn't arrived yet, which matters for
    // name coverage under a busy feed. Prioritise authors we DON'T yet have so a
    // huge author list can't starve the un-resolved ones.
    final have = <String>[];
    final missing = <String>[];
    for (final p in _profTracked) {
      // _hasProfile, NOT profileOf: this walks every tracked author, and
      // profileOf is a SQLite query each time. Under a public firehose a new
      // author arrives constantly, so this pass ran every couple of seconds
      // over the full 500-author window — ~250 queries/s, which pinned a core
      // on a slow phone and ANR'd it. The cache answers the same question and
      // is kept honest by _onEvent, which adds to _haveProfile the moment a
      // kind-0 is stored.
      (_hasProfile(p) ? have : missing).add(p);
    }
    final authors = [...missing, ...have];
    final prev = _profSub;
    if (prev != null) {
      _subFilters.remove(prev);
      _inbox.remove(prev);
      _seen.remove(prev);
      for (final c in _clients.values) {
        c.unsubscribe(prev);
      }
    }
    final sub = 'prof${_subSeq++}';
    _profSub = sub;
    final f = [
      NostrFilter(kinds: const [0], authors: authors),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  /// Stored kind-1 replies to [postId] (events that #e it), oldest first.
  List<NostrEvent> repliesTo(String postId) {
    final evs = store.query(
      NostrFilter(
        kinds: const [1],
        tags: {
          'e': [postId],
        },
      ),
    );
    final out =
        evs
            .where(
              (e) => e.tags.any(
                (t) => t.length >= 2 && t[0] == 'e' && t[1] == postId,
              ),
            )
            .toList()
          ..sort((a, b) => a.createdAt.compareTo(b.createdAt));
    return out;
  }

  /// The latest stored kind-0 profile event for [pub], if any.
  /// Sqlite profile lookups performed — counted because an unbounded re-query
  /// of absent profiles once pegged an entire core with nothing to show for it.
  int profileLookups = 0;

  /// One event by id, from the store (it is there once any relay delivered it).
  NostrEvent? eventById(String id) {
    if (id.length != 64) return null;
    final evs = store.query(NostrFilter(ids: [id], limit: 1));
    return evs.isEmpty ? null : evs.first;
  }

  /// Ask the relays for an event we do not hold yet (a notification about a
  /// post this device never saw in its own feed, say).
  void fetchEvent(String id) {
    if (id.length != 64) return;
    final sub = 'ev${_subSeq++}';
    final f = [
      NostrFilter(ids: [id], limit: 1),
    ];
    _subFilters[sub] = f;
    _inbox[sub] = Queue<NostrEvent>();
    _seen[sub] = <String>{};
    for (final e in _endpoints.values) {
      if (e.enabled) _clients[e.uri]?.subscribe(sub, f);
    }
  }

  /// Everything anyone has done to MY posts — reactions, replies, reposts and
  /// mentions — newest first, READ FROM THE LOCAL STORE.
  ///
  /// This is the whole point of keeping them at tier `self`: the notification
  /// list is answerable with the relays unreachable and after a restart, which
  /// an in-memory list drained from a live subscription never was.
  List<NostrEvent> myNotifications({int limit = 100}) {
    final me = selfPubkey;
    if (me == null) return const [];
    final evs = store.query(
      NostrFilter(
        kinds: const [1, 6, 7],
        tags: {
          'p': [me],
        },
        limit: limit,
      ),
    );
    final out = [
      for (final e in evs)
        if (e.pubkey != me) e,
    ];
    out.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return out;
  }

  NostrEvent? profileOf(String pub) {
    profileLookups++;
    final evs = store.query(NostrFilter(kinds: const [0], authors: [pub]));
    NostrEvent? best;
    for (final e in evs) {
      if (best == null || e.createdAt > best.createdAt) best = e;
    }
    return best;
  }

  // Delivery rate cap: bounds the SQLite/dispatch work this (UI/engine) isolate
  // does per second, so a public firehose is SAMPLED instead of flooding the
  // main thread. A followed/web-of-trust feed is low-volume and never trips it.
  static const int _rateWindowMs = 250;
  static const int _rateMaxPerWindow =
      15; // ~60 events/s ceiling (main-thread SQLite)
  int _rateWindowStart = 0;
  int _rateCount = 0;
  int rateDropped = 0;

  /// Inbound-event accounting. The relay firehose is the engine isolate's whole
  /// workload, so these are what attribute (and bound) its CPU.
  int eventsSeen = 0;
  int eventsStored = 0;
  int reactionsStored = 0;

  Map<String, int> drainEventStats() {
    final out = {
      'seen': eventsSeen,
      'stored': eventsStored,
      'reactions': reactionsStored,
      'dropped': rateDropped,
      'profileLookups': profileLookups,
    };
    eventsSeen = 0;
    eventsStored = 0;
    reactionsStored = 0;
    rateDropped = 0;
    profileLookups = 0;
    return out;
  }

  /// Is this event mine — my post, or someone's reaction/reply/repost OF my
  /// post (it p-tags me)?
  bool _isMine(NostrEvent event) {
    final me = selfPubkey;
    if (me == null) return false;
    if (event.pubkey == me) return true;
    for (final t in event.tags) {
      if (t.length >= 2 && t[0] == 'p' && t[1] == me) return true;
    }
    return false;
  }

  /// Signature check, paid once per event id — and ONLY for events we are
  /// about to keep, deliver or persist. Verification is pure-Dart BigInt
  /// Schnorr (~100ms on a budget phone). Verifying every delivery inline —
  /// which is what the ws client used to do — pegged this isolate at 100% of a
  /// core on the kind-7 firehose alone (profiler: 75% of samples in BigInt),
  /// and everything sharing the isolate starved: the edition timers, the port
  /// messages, the websocket handshakes. The content gate rejects most of the
  /// firehose for free; only the survivors are worth cryptography.
  final Set<String> _verifiedIds = <String>{};
  static const int _verifiedMax = 8000;
  bool _verify(NostrEvent e) {
    final id = e.id;
    if (id == null || id.isEmpty) return false;
    if (e.preVerified || _verifiedIds.contains(id)) return true;
    if (!e.verify()) return false;
    e.preVerified = true;
    _verifiedIds.add(id);
    while (_verifiedIds.length > _verifiedMax) {
      _verifiedIds.remove(_verifiedIds.first);
    }
    return true;
  }

  void _onEvent(String subId, NostrEvent event) {
    eventsSeen++;
    lastRelayFrameMs = DateTime.now().millisecondsSinceEpoch; // paces the engine

    // MY OWN CORNER OF THE NETWORK IS NOT CACHE.
    //
    // A reaction to my post is a fact about me, and this is an off-grid app:
    // the relay that delivered it may be unreachable for days. It is stored
    // here, at tier `self`, BEFORE the reaction short-circuit and BEFORE the
    // firehose rate cap — both of which used to drop it on the floor, so the
    // notification list survived only as long as the process did, and opening
    // the post it was about went back to the network for something we had
    // already been given.
    if (_isMine(event) && _verify(event)) {
      if (store.put(event, tier: 0)) {
        eventsStored++;
        onStored?.call(event);
      }
      final ref = _firstETag(event);
      if (event.kind == NostrEventKind.reaction && ref != null) {
        store.addReaction(ref, event.pubkey);
      }
    }
    // Persist reaction receipts (post id + reactor) so like totals survive a
    // restart instead of crawling back over the network.
    //
    // ONLY for posts we actually track. The discovery subscription is a kind-7
    // firehose across every public relay, and persisting all of it meant one
    // unbatched sqlite INSERT per inbound reaction — thousands a minute, ahead
    // of the rate cap, burning the engine isolate for rows no one would ever
    // read. Tracked posts are exactly the ones the UI displays (trackStats
    // registers them, and seeds their tallies back from these rows), so this is
    // the whole set the persistence was ever for.
    if (event.kind == NostrEventKind.reaction) {
      final liked = _firstETag(event);
      // Persisted receipts are attributable, so they are verified — but only
      // for TRACKED posts, which keeps the crypto bounded by what is on
      // screen. The in-memory tallies below stay unverified on purpose: they
      // are display hints on a bounded map, and the post itself is verified
      // before it is ever shown.
      if (liked != null &&
          _statReact.containsKey(liked) &&
          _verify(event)) {
        if (store.addReaction(liked, event.pubkey)) reactionsStored++;
      }
    }
    // Engagement (likes/replies) is tallied for on-screen posts BEFORE the rate
    // cap so counts stay accurate. Reactions are tally-only (never displayed).
    final wasReaction = _tallyStats(event);
    // Reactions also drive the discovery tally; both consume the reaction here.
    if (_discoTally(event)) return;
    if (wasReaction) return;

    final now = DateTime.now().millisecondsSinceEpoch;

    // The firehose has its own rules: the QUALITY GATE decides whether this is
    // stored and shown at all, so it never reaches the generic path below.
    //
    // It runs BEFORE the rate cap, and that ordering is the whole point. The cap
    // used to come first and it ate the All feed alive: relays answer a fresh
    // kind-1 subscription with a burst (200 events each, times every relay), the
    // cap is 15 per 250ms, so the burst was discarded WITHOUT the gate ever
    // seeing it — `dropped=173, fireSeen=0, stored=0` while four relays were
    // happily streaming. The cap exists to protect the STORE from a firehose of
    // junk, and the gate already does that job better: it stores only what it
    // would show. Everything it rejects costs one cheap in-memory verdict.
    if (subId == _fireSub) {
      _onFirehose(event, now);
      return;
    }

    // A PROFILE IS NEVER SHED. It is the key that unlocks held posts.
    //
    // kind-0 answers arrive as a burst — one batch REQ of 100 authors, answered
    // by every relay at once — which is precisely the shape the rate cap is built
    // to throw away. So the cap was destroying the very events that release the
    // firehose's pending queue: posts were held waiting for a name, the name was
    // dropped on the floor 15-per-250ms, and three minutes later the post was
    // discarded. `pending` climbed while `kept` stayed at zero, for hours.
    //
    // Handling it here — ahead of the cap — costs one cheap map insert per
    // profile. The store write it triggers is bounded by how many authors we
    // asked about, which we control.
    if (event.kind == NostrEventKind.setMetadata) {
      _releaseProfile(event, now);
      return;
    }

    // The generic path stores EVERYTHING it is handed, so it keeps the cap.
    if (now - _rateWindowStart >= _rateWindowMs) {
      _rateWindowStart = now;
      _rateCount = 0;
    }
    if (_rateCount >= _rateMaxPerWindow) {
      rateDropped++; // overflow — dropped before it can reach sqlite
      return;
    }
    _rateCount++;

    // Merge into the unified store (dedup + replaceable/deletion handled there).
    if (!_verify(event)) return;
    if (store.put(event)) {
      eventsStored++;
      onStored?.call(event);
    }

    // A liked-enough post (fetched by id) goes to EVERY discovery subscriber.
    if (_discoSubscribers.isNotEmpty &&
        event.kind == NostrEventKind.textNote &&
        event.id != null &&
        _discoWanted.contains(event.id)) {
      for (final id in _discoSubscribers) {
        _bufferForSub(id, event);
      }
    }
    _bufferForSub(subId, event);
    // Bound the seen-set by EVICTING the oldest, never by emptying it. Clearing
    // it wholesale meant the next thing a relay re-sent (and relays re-send
    // their recent window on every re-open) looked new again — the same post,
    // buffered a second time, shown twice in the feed.
    final seen = _seen[subId];
    if (seen != null) {
      while (seen.length > _maxInbox * 4) {
        seen.remove(seen.first);
      }
    }
  }

  /// Pop up to [max] buffered events for a subscription (oldest first), as JSON.
  /// Empty when the inbox is drained — the wapp polls this each tick.
  List<Map<String, dynamic>> drainEvents(String subId, {int max = 50}) {
    var inbox = _inbox[subId];
    if (inbox == null) {
      // Self-heal a firehose subscription the caller is still draining.
      //
      // The wapp acquires its firehose subId ONCE and drains it every tick,
      // forever; it only re-subscribes when its cached id is empty. But the hub
      // tears the firehose down 6s after the last subscriber leaves (Social
      // closed) and can churn its lifecycle, which deletes this inbox and drops
      // the id from _fireSubscribers. The wapp never notices — it keeps draining
      // a corpse, so the "All" feed freezes at its last edition while the
      // launcher Hero stays fresh (the Hero re-acquires its subId every cycle
      // with `??=`, which is the ONLY reason it self-heals and the wapp did not).
      //
      // So: draining a firehose id is itself the signal that a consumer wants it
      // live. Resurrect it here — re-register the subscriber, recreate the inbox,
      // re-arm the REQ and schedule a catch-up edition — and the wapp gets the
      // Hero's self-healing for free, with no wapp rebuild. It costs one
      // re-subscribe on the first drain after a teardown; every drain after finds
      // the inbox and takes this branch never again.
      if (subId.startsWith('fire')) {
        subscribeFirehoseWithId(subId);
        inbox = _inbox[subId];
      }
      if (inbox == null) return const [];
    }
    final out = <Map<String, dynamic>>[];
    while (inbox.isNotEmpty && out.length < max) {
      final event = inbox.removeFirst();
      final json = event.toJson();
      final id = event.id;
      if (id != null) {
        final meta = _fireBatchMeta[subId]?.remove(id);
        if (meta != null) json.addAll(meta);
      }
      out.add(json);
    }
    return out;
  }

  /// Publish an event to the local store + every enabled relay. Our own event
  /// is also surfaced to matching open subscriptions so the feed shows it
  /// immediately (it won't arrive back over a relay for a moment).
  Future<void> publish(NostrEvent event) async {
    if (store.put(event, tier: 0)) onStored?.call(event);
    for (final e in _subFilters.entries) {
      if (e.value.any((f) => NostrWire.matches(f, event))) {
        _bufferForSub(e.key, event);
      }
    }
    for (final e in _endpoints.values) {
      if (!e.enabled) continue;
      // ignore: discarded_futures
      _clients[e.uri]?.publish(event);
    }
  }

  void _bufferForSub(String subId, NostrEvent event) {
    final inbox = _inbox[subId];
    final seen = _seen[subId];
    if (inbox == null || seen == null || event.id == null) return;
    if (!seen.add(event.id!)) return;
    inbox.add(event);
    while (inbox.length > _maxInbox) {
      inbox.removeFirst();
    }
  }

  Future<void> close() async {
    _discoTimer?.cancel();
    _discoTimer = null;
    _fireWatchdog?.cancel();
    _fireWatchdog = null;
    _fireProfTimer?.cancel();
    _fireProfTimer = null;
    _statDebounce?.cancel();
    _statDebounce = null;
    _profDebounce?.cancel();
    _profDebounce = null;
    for (final c in _clients.values) {
      await c.close();
    }
    _clients.clear();
  }
}
