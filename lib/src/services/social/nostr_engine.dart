/*
 * NostrEngine — runs the ENTIRE NOSTR relay pipeline on a dedicated background
 * isolate, so the UI isolate never touches it.
 *
 * The UI isolate saturating on a public firehose (hundreds of frames/s × N
 * relays) was the root of the "app not responding" reports: WebSocket receive,
 * JSON decode, BIP-340 verify, SQLite writes, and the like/reply/profile tallies
 * all ran on the main isolate. Here every one of those runs inside the engine
 * isolate. The main side ([NostrClient]) only:
 *   - sends fire-and-forget COMMANDS (subscribe, publish, track, …), and
 *   - reads lazily-updated CACHES that the engine refreshes on a timer.
 * Nothing on the UI isolate ever blocks on relay work.
 *
 * Messages are plain sendable maps/lists (no shared objects). Events cross the
 * boundary as their NIP-01 JSON, which is exactly what the wapp consumes anyway.
 */
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';

import 'package:sqlite3/open.dart' as sqlite_open;

import '../../util/nostr_crypto.dart';
import '../../util/nostr_event.dart';
import 'nostr_relay_hub.dart';
import 'relay_event_store.dart';

/// Init payload handed to the freshly-spawned engine isolate.
class _EngineInit {
  final SendPort toMain;
  final String storePath;
  final String? persistPath;
  final String? selfPubHex;

  /// Native SQLite library to load ON THIS ISOLATE, e.g. 'libsqlcipher.so'.
  ///
  /// package:sqlite3's loader override is PER-ISOLATE. A host that bundles
  /// SQLCipher instead of stock SQLite (aurora does, for encrypted profiles)
  /// sets its override on the main isolate — and the engine isolate then
  /// tries to load a libsqlite3.so that is not in the app at all, throws, and
  /// the whole NOSTR pipeline silently never starts.
  final String? sqliteLibrary;

  /// SQLCipher key (raw hex) for [storePath]. Null = plain database.
  final String? dbKeyHex;

  const _EngineInit(
    this.toMain,
    this.storePath,
    this.persistPath,
    this.selfPubHex, {
    this.sqliteLibrary,
    this.dbKeyHex,
  });
}

/// Main-isolate proxy: mints subscription ids, forwards commands to the engine,
/// and serves the wapp from caches the engine refreshes. Every method here is
/// cheap (a map lookup or a port send) — no relay/SQLite work on this isolate.
class NostrClient {
  NostrClient._();

  Isolate? _iso;
  SendPort? _toEngine;
  final ReceivePort _fromEngine = ReceivePort();
  bool _ready = false;
  final List<Map<String, dynamic>> _preReady =
      []; // commands queued pre-handshake

  int _subSeq = 0;

  // ── Caches (refreshed by engine snapshots) ─────────────────────────────────
  List<Map<String, dynamic>> _relays = const [];

  /// Inbound-event rates from the engine isolate (seen/stored/reactions/
  /// dropped per push window). The relay firehose IS this isolate's workload,
  /// so this is how the host attributes its CPU. Reset each engine push.
  Map<String, int> _eventStats = const {};
  Map<String, int> get eventStats => _eventStats;
  final Map<String, List<Map<String, dynamic>>> _subEvents =
      {}; // subId → queue
  final Map<String, (int, int, bool)> _stats =
      {}; // eventId → (likes,replies,mine)
  // eventId → (upvotes, downvotes, myVote ∈ {-1,0,1}). NIP-25 puts the verdict
  // in the reaction's content: "-" is a downvote, anything else is a like.
  final Map<String, (int, int, int)> _votes = {};

  /// Single events fetched by id (see [eventById]).
  final Map<String, Map<String, dynamic>> _events = {};

  /// Reactions/replies/reposts/mentions of MY posts, newest first, as the
  /// engine reads them out of the local store.
  List<Map<String, dynamic>> _notifications = const [];
  List<Map<String, dynamic>> get notifications => _notifications;

  /// Turn a relay on/off (it stays in the list).
  void setRelayEnabled(String uri, bool on) =>
      _send({'cmd': 'relayEnable', 'uri': uri, 'on': on});

  /// Tell the engine (and its store) who we are.
  void setSelfPubkey(String pub) {
    if (pub.length != 64) return;
    _send({'cmd': 'selfPub', 'pub': pub});
  }

  final Set<String> _likedLocally = {}; // ids we've liked (keep them filled)
  final Map<String, Map<String, String>> _profiles = {}; // pub → profile
  final Map<String, Map<String, String>> _profByShort12 =
      {}; // pub[:12] → profile
  final Set<String> _profileRequested = {};
  final Map<String, List<Map<String, dynamic>>> _replies =
      {}; // postId → replies
  List<String> _myFollows = const []; // my kind-3 contact list (hex pubkeys)
  bool _myFollowsLoaded = false;
  int _myFollowsVersion = 0;
  static const int _subQueueMax = 800;

  /// Optional: notified (throttled) when caches change, so the UI can repaint.
  void Function()? onChanged;

  /// Engine-side log lines (e.g. a store that refused to open). The host
  /// pipes these into its own log so a dead pipeline is never silent.
  ///
  /// Setting it flushes whatever the engine already said: the isolate reports
  /// a failed store open in its constructor, which is BEFORE spawn() has even
  /// returned to the host — those lines used to fall on the floor, which is
  /// how a completely dead NOSTR pipeline stayed invisible.
  void Function(String msg)? get onLog => _onLog;
  set onLog(void Function(String msg)? f) {
    _onLog = f;
    if (f == null) return;
    for (final l in _logBuffer) {
      f(l);
    }
    _logBuffer.clear();
  }

  void Function(String msg)? _onLog;
  final List<String> _logBuffer = [];

  static Future<NostrClient> spawn({
    required String storePath,
    String? persistPath,
    String? selfPubHex,
    String? sqliteLibrary,
    String? dbKeyHex,
  }) async {
    final c = NostrClient._();
    c._fromEngine.listen(c._onFromEngine);
    c._iso = await Isolate.spawn(
      _engineMain,
      _EngineInit(
        c._fromEngine.sendPort,
        storePath,
        persistPath,
        selfPubHex,
        sqliteLibrary: sqliteLibrary,
        dbKeyHex: dbKeyHex,
      ),
      debugName: 'nostr-engine',
    );
    return c;
  }

  void _send(Map<String, dynamic> cmd) {
    final p = _toEngine;
    if (p == null) {
      _preReady.add(cmd);
    } else {
      p.send(cmd);
    }
  }

  void _onFromEngine(dynamic msg) {
    if (msg is SendPort) {
      _toEngine = msg;
      _ready = true;
      for (final c in _preReady) {
        msg.send(c);
      }
      _preReady.clear();
      return;
    }
    if (msg is! Map) return;
    final line = msg['log'];
    if (line is String) {
      final sink = _onLog;
      if (sink != null) {
        sink(line);
      } else if (_logBuffer.length < 100) {
        _logBuffer.add(line);
      }
      return;
    }
    switch (msg['snap']) {
      case 'relays':
        _relays = (msg['json'] as List).cast<Map<String, dynamic>>();
      case 'evstats':
        _eventStats = (msg['stats'] as Map).cast<String, int>();
      case 'fhstats':
        // ACCUMULATE. The engine drains this every 400ms, so one snapshot is a
        // 400ms window — and the log reads it once a minute. Treating a snapshot
        // as a per-minute total is what made the telemetry say "seen=0" while
        // events were arriving, and sent me hunting a network fault that was not
        // there. Gauges (held/pending) take the latest value; counters add up.
        final snap = (msg['stats'] as Map).cast<String, int>();
        final acc = Map<String, int>.from(firehoseStats);
        for (final e in snap.entries) {
          if (e.key == 'held' || e.key == 'pending') {
            acc[e.key] = e.value; // a gauge, not a counter
          } else {
            acc[e.key] = (acc[e.key] ?? 0) + e.value;
          }
        }
        firehoseStats = acc;
      case 'events':
        final sub = msg['subId'] as String;
        final q = _subEvents.putIfAbsent(sub, () => []);
        q.addAll((msg['events'] as List).cast<Map<String, dynamic>>());
        if (q.length > _subQueueMax) {
          q.removeRange(0, q.length - _subQueueMax);
        }
      case 'stats':
        (msg['entries'] as Map).forEach((k, v) {
          final l = (v as List);
          var likes = l[0] as int;
          var mine = l[2] as bool;
          if (_likedLocally.contains('$k')) {
            mine = true; // keep our own like filled until the engine confirms
            if (likes < 1) likes = 1;
          }
          _stats['$k'] = (likes, l[1] as int, mine);
          if (l.length >= 6) {
            var up = l[3] as int;
            var down = l[4] as int;
            var my = l[5] as int;
            final local = _votedLocally['$k'];
            if (local != null) {
              my = local; // hold our own vote until the engine confirms it
              if (local > 0 && up < 1) up = 1;
              if (local < 0 && down < 1) down = 1;
            }
            _votes['$k'] = (up, down, my);
          }
        });
      case 'profiles':
        (msg['entries'] as Map).forEach((k, v) {
          final m = (v as Map).cast<String, String>();
          _profiles['$k'] = m;
          if ('$k'.length >= 12) _profByShort12['$k'.substring(0, 12)] = m;
        });
      case 'notifications':
        _notifications = (msg['events'] as List)
            .map((e) => (e as Map).cast<String, dynamic>())
            .toList();
      case 'event':
        _events['${msg['id']}'] = (msg['event'] as Map).cast<String, dynamic>();
      case 'replies':
        _replies['${msg['id']}'] = (msg['events'] as List)
            .cast<Map<String, dynamic>>();
      case 'myFollows':
        _myFollows = (msg['pubs'] as List).cast<String>();
        _myFollowsLoaded = true;
        _myFollowsVersion++;
      case 'verified':
        final c = _verifyWaiters.remove('${msg['req']}');
        c?.complete((msg['events'] as List).cast<Map<String, dynamic>>());
        return; // not a UI-visible change
      case 'refreshBurstDone':
        final c = _refreshWaiters.remove('${msg['req']}');
        c?.complete((msg['count'] as int?) ?? 0);
        return;
    }
    onChanged?.call();
  }

  int _verifySeq = 0;
  final Map<String, Completer<List<Map<String, dynamic>>>> _verifyWaiters = {};
  int _refreshSeq = 0;
  final Map<String, Completer<int>> _refreshWaiters = {};

  /// Verify a batch of events **on the engine isolate** and return the ones
  /// whose signatures hold.
  ///
  /// This is the door for anything that arrived over Reticulum: RNS runs on the
  /// main isolate, so verifying a peer's batch there would put secp256k1 on the
  /// UI thread. Hand the bytes here instead, then store the survivors with
  /// [RelayEventStore.putAllVerified].
  Future<List<Map<String, dynamic>>> verifyEvents(
    List<Map<String, dynamic>> events, {
    Duration timeout = const Duration(seconds: 20),
  }) async {
    if (events.isEmpty) return const [];
    final req = 'v${_verifySeq++}';
    final c = Completer<List<Map<String, dynamic>>>();
    _verifyWaiters[req] = c;
    _send({'cmd': 'verify', 'req': req, 'events': events});
    return c.future.timeout(
      timeout,
      onTimeout: () {
        _verifyWaiters.remove(req);
        return const [];
      },
    );
  }

  bool get ready => _ready;

  // ── Relay list ──────────────────────────────────────────────────────────
  List<Map<String, dynamic>> relaysJson() => _relays;

  bool addRelay(String uri) {
    final u = uri.trim();
    if (u.isEmpty) return false;
    if (_relays.any((r) => r['uri'] == u)) return false;
    _send({'cmd': 'addRelay', 'uri': u});
    // Optimistic: show it immediately as connecting.
    _relays = [
      ..._relays,
      {
        'uri': u,
        'scheme': _schemeOf(u),
        'enabled': true,
        'status': 'connecting',
      },
    ];
    return true;
  }

  bool removeRelay(String uri) {
    if (!_relays.any((r) => r['uri'] == uri)) return false;
    _send({'cmd': 'removeRelay', 'uri': uri});
    _relays = _relays.where((r) => r['uri'] != uri).toList();
    return true;
  }

  static String _schemeOf(String u) =>
      u.startsWith('wss://') || u.startsWith('ws://')
      ? 'websocket'
      : (u.startsWith('rns://')
            ? 'reticulum'
            : (u == 'local' ? 'local' : 'unknown'));

  // ── Subscriptions ─────────────────────────────────────────────────────────
  String subscribe(List<NostrFilter> filters) {
    final subId = 's${_subSeq++}';
    _subEvents[subId] = [];
    _send({
      'cmd': 'subscribe',
      'subId': subId,
      'filters': [for (final f in filters) f.toJson()],
    });
    return subId;
  }

  String subscribeDiscovery({int minLikes = 2}) {
    final subId = 'd${_subSeq++}';
    _subEvents[subId] = [];
    _send({'cmd': 'discovery', 'subId': subId, 'minLikes': minLikes});
    return subId;
  }

  /// The live firehose: kind-1 as the relays push it, passed through the quality
  /// gate. This is what an "All" feed is supposed to be — discovery (above) can
  /// only surface posts that already collected likes, so it is a *popular* feed
  /// and can never be a fresh one.
  String subscribeFirehose({bool requireProfile = true}) {
    final subId = 'f${_subSeq++}';
    _subEvents[subId] = [];
    _send({
      'cmd': 'firehose',
      'subId': subId,
      'requireProfile': requireProfile,
    });
    return subId;
  }

  /// Self + follows: they bypass the firehose gate. Push this whenever the
  /// follow set changes.
  void setTrustedAuthors(Iterable<String> pubs) =>
      _send({'cmd': 'trusted', 'pubs': pubs.toList()});

  /// Authors the user muted — never shown, whatever they post.
  void setMutedAuthors(Iterable<String> pubs) =>
      _send({'cmd': 'muted', 'pubs': pubs.toList()});

  /// Pull-to-refresh: fetch, rank and hand the feed up to [n] new posts.
  Future<int> refreshBurst({int n = 100}) {
    final req = 'r${_refreshSeq++}';
    final completer = Completer<int>();
    _refreshWaiters[req] = completer;
    _send({'cmd': 'refreshBurst', 'req': req, 'n': n});
    return completer.future.timeout(
      const Duration(seconds: 25),
      onTimeout: () {
        _refreshWaiters.remove(req);
        return 0;
      },
    );
  }

  /// App resumed / user pulled to refresh: recover zombie sockets and refetch
  /// the missed window.
  void resumeNetwork() => _send({'cmd': 'resume'});

  /// Deadline heartbeat from Android's native foreground service. Work remains
  /// in the engine isolate; the UI isolate only sends this small command.
  void backgroundTick(int nowMs) =>
      _send({'cmd': 'backgroundTick', 'nowMs': nowMs});

  Future<int> resumeAndRefreshFirehose({int n = 100}) {
    final req = 'r${_refreshSeq++}';
    final completer = Completer<int>();
    _refreshWaiters[req] = completer;
    _send({'cmd': 'resumeRefresh', 'req': req, 'n': n});
    return completer.future.timeout(
      const Duration(seconds: 25),
      onTimeout: () {
        _refreshWaiters.remove(req);
        return 0;
      },
    );
  }

  /// Firehose accounting: kept / pending / expired, plus a count per drop
  /// reason. Empty until the first firehose subscription exists.
  Map<String, int> firehoseStats = const {};

  /// Read AND reset the accumulated counters (gauges are left alone). Each log
  /// line is then "what happened in the last minute", which is the only reading
  /// that can be acted on.
  Map<String, int> drainFirehoseStatsForLog() {
    final out = Map<String, int>.from(firehoseStats);
    firehoseStats = {
      for (final e in firehoseStats.entries)
        if (e.key == 'held' || e.key == 'pending') e.key: e.value,
    };
    return out;
  }

  void unsubscribe(String subId) {
    _subEvents.remove(subId);
    _send({'cmd': 'unsubscribe', 'subId': subId});
  }

  List<Map<String, dynamic>> drainEvents(String subId, {int max = 50}) {
    final q = _subEvents[subId];
    if (q == null || q.isEmpty) return const [];
    final n = q.length < max ? q.length : max;
    final out = q.sublist(0, n);
    q.removeRange(0, n);
    return out;
  }

  // ── Publish (main signs, engine sends) ──────────────────────────────────
  Future<void> publish(NostrEvent event) async =>
      _send({'cmd': 'publish', 'event': event.toJson()});

  // ── Engagement ────────────────────────────────────────────────────────────
  void trackStats(List<String> ids) {
    final wanted = ids.where((id) => id.length == 64).toList();
    if (wanted.isEmpty) return;
    _send({'cmd': 'trackStats', 'ids': wanted});
  }

  (int, int, bool) statsOf(String id, String? selfPub) =>
      _stats[id] ?? (0, 0, false);

  /// (upvotes, downvotes, myVote) for a post.
  (int, int, int) votesOf(String id) => _votes[id] ?? (0, 0, 0);

  final Map<String, int> _votedLocally = {};

  /// Our own vote: 1 up, -1 down, 0 retracted. Bumps the count locally so the
  /// thumb fills at once instead of after a relay round-trip.
  void recordVote(String id, String pub, int vote) {
    _votedLocally[id] = vote;
    final cur = _votes[id] ?? (0, 0, 0);
    var up = cur.$1, down = cur.$2;
    if (vote > 0) {
      if (cur.$3 <= 0) up += 1;
      if (cur.$3 < 0 && down > 0) down -= 1;
    } else if (vote < 0) {
      if (cur.$3 >= 0) down += 1;
      if (cur.$3 > 0 && up > 0) up -= 1;
    }
    _votes[id] = (up, down, vote);
    _send({'cmd': 'recordVote', 'id': id, 'pub': pub, 'vote': vote});
  }

  void recordReaction(String id, String pub) {
    // Optimistic local bump so the heart fills before it round-trips.
    _likedLocally.add(id);
    final cur = _stats[id] ?? (0, 0, false);
    if (!cur.$3) _stats[id] = (cur.$1 + 1, cur.$2, true);
    _send({'cmd': 'recordReaction', 'id': id, 'pub': pub});
  }

  /// One event by id. Returns it when we hold it; otherwise asks the engine
  /// (and the relays) for it and answers null — call again once it lands.
  Map<String, dynamic>? eventById(String id) {
    final have = _events[id];
    if (have != null) return have;
    _send({'cmd': 'fetchEvent', 'id': id});
    return null;
  }

  // ── Profiles ──────────────────────────────────────────────────────────────
  void trackProfile(String pub) {
    if (pub.length != 64 || !_profileRequested.add(pub)) return;
    _send({'cmd': 'trackProfile', 'pub': pub});
  }

  /// Parsed profile map (name/pic/about/nip05/website/lud16/banner/npub) or {}.
  Map<String, String> profile(String pub) {
    trackProfile(pub); // ensure it's being fetched
    return _profiles[pub] ?? const {};
  }

  /// Resolve a profile by the 12-char pubkey prefix the UI uses as a post's
  /// `from`. Backed by the engine's PERSISTENT store (every kind-0 ever seen is
  /// broadcast to this index at startup), so authors resolve even when they're
  /// not in the current live feed (Saved tab, old threads). {} if unknown.
  Map<String, String> profileByShort12(String short12) =>
      _profByShort12[short12] ?? const {};

  /// My kind-3 contact list (hex pubkeys), fetched from the relays.
  List<String> myFollows() => _myFollows;

  /// Whether a kind-3 event has been loaded. A loaded empty list is distinct
  /// from startup, while the relay snapshot is still unknown.
  bool get myFollowsLoaded => _myFollowsLoaded;
  int get myFollowsVersion => _myFollowsVersion;

  // ── Replies ─────────────────────────────────────────────────────────────
  List<Map<String, dynamic>> replies(String postId) {
    _send({'cmd': 'fetchReplies', 'id': postId}); // refresh (lazy)
    return _replies[postId] ?? const [];
  }

  Future<void> close() async {
    _send({'cmd': 'close'});
    await Future<void>.delayed(const Duration(milliseconds: 50));
    _iso?.kill(priority: Isolate.immediate);
    _iso = null;
    _fromEngine.close();
  }

  /// Last message the isolate guard reported, and how many identical ones it
  /// has swallowed since. Static because the guard outlives every object here.
  static String _lastGuardMsg = '';
  static int _lastGuardMs = 0;
  static int _guardRepeats = 0;

  // ══ engine isolate ════════════════════════════════════════════════════════
  static Future<void> _engineMain(_EngineInit init) async {
    // Guard the whole isolate. An unhandled async error here is FATAL by
    // default: the isolate dies and the feed goes quiet with nothing but a
    // stack trace on stderr to say why. dart:io itself supplies such an error
    // — closing a wss relay socket while a read event is already queued throws
    // "SocketException: Reading from a closed socket" from a dart:io timer, in
    // no stream we listen to, so no onError can catch it. Logged and survived.
    runZonedGuarded(() {
      // The sqlite3 loader override is per-isolate: re-apply the host's choice
      // of native library here, BEFORE anything opens a database.
      final lib = init.sqliteLibrary;
      if (lib != null && lib.isNotEmpty) {
        DynamicLibrary open() => DynamicLibrary.open(lib);
        for (final os in sqlite_open.OperatingSystem.values) {
          sqlite_open.open.overrideFor(os, open);
        }
      }
      // All store/relay setup runs on THIS (background) isolate.
      final engine = _Engine(
        init.toMain,
        init.storePath,
        init.persistPath,
        init.selfPubHex,
        dbKeyHex: init.dbKeyHex,
      );
      final rx = ReceivePort();
      init.toMain.send(rx.sendPort);
      rx.listen((dynamic m) {
        if (m is Map) engine.handle(m.cast<String, dynamic>());
      });
    }, (e, st) {
      // COALESCED, and that is not tidiness. This sent one port message to
      // main per error, and the error above is one dart:io produces in a tight
      // loop: measured on a phone, 800 identical lines in 56 ms -- about
      // 14,000 messages a second, each one an allocation on main and a row in
      // a log ring that has held 50 MB before now (docs/performance.md 3.3).
      // The guard is meant to keep the isolate alive, not to hand the main
      // isolate a denial of service; an error that repeats is one fact,
      // however many times it happens.
      final msg = 'nostr-engine: unhandled $e';
      final now = DateTime.now().millisecondsSinceEpoch;
      if (msg == _lastGuardMsg && now - _lastGuardMs < 5000) {
        _guardRepeats++;
        return;
      }
      final repeated = _guardRepeats;
      _lastGuardMsg = msg;
      _lastGuardMs = now;
      _guardRepeats = 0;
      init.toMain.send({
        'log': repeated > 0 ? '$msg (x${repeated + 1} suppressed)' : msg,
      });
    });
  }
}

/// The actual worker living on the background isolate.
class _Engine {
  final SendPort toMain;
  String? selfPub; // learned from the first reaction if unset at spawn
  late final RelayEventStore _store;
  late final NostrRelayHub _hub;
  final Set<String> _drainSubs = {}; // wapp-facing subs to push to main
  final Set<String> _wantEvents = {}; // ids asked for, not yet in the store
  String _notifSig = '';
  final Map<String, (int, int, bool, int, int, int)> _statsSent = {};
  final Set<String> _profSent = {};
  bool _myFollowsSub = false; // subscribed my kind-3 yet
  Set<String>? _myFollowsSent; // last contact-list set sent to main
  Timer? _timer;
  int _tickN = 0;
  int _healthTick = 0;
  bool _ok = false;

  _Engine(
    this.toMain,
    String storePath,
    String? persistPath,
    this.selfPub, {
    String? dbKeyHex,
  }) {
    try {
      _store = RelayEventStore.open(storePath, keyHex: dbKeyHex);
      _hub = NostrRelayHub(
        store: NostrStore.of(_store),
        persistPath: persistPath,
        rnsClientFactory:
            null, // RNS lives on the main isolate; wss + local here
        // Relay connects, drops and refusals go to the host log. Without this
        // a feed that never fills is indistinguishable from a feed with
        // nothing in it.
        log: (m) => toMain.send({'log': m}),
        // Only a newly-stored contact list can change our follow set, so that
        // is the only thing that makes _syncMyFollows do its (expensive) work.
        onStored: (e) {
          _storedSinceNotif = true; // the notifications join has new input
          if (e.kind == NostrEventKind.contacts && e.pubkey == selfPub) {
            _myFollowsDirty = true;
          }
        },
      );
      // ignore: discarded_futures
      _hub.selfPubkey = selfPub;
      _hub.init();
      _ok = true;
      _sendStoredProfiles(); // hydrate the UI's profile index from disk
      _scheduleTick();
    } catch (e) {
      // A dead engine used to be SILENT — no relay ever connected and the feed
      // was simply empty forever, with nothing in the log to say why. Say it.
      _ok = false;
      toMain.send({'log': 'NOSTR engine failed to start: $e'});
    }
  }

  /// Broadcast EVERY kind-0 profile already in the persistent store to the main
  /// isolate at startup, so authors resolve in every view (Saved, old threads,
  /// profile page) without being in the current live feed.
  void _sendStoredProfiles() {
    try {
      final evs = _store.query(const NostrFilter(kinds: [0], limit: 5000));
      final seen = <String>{};
      final entries = <String, Map<String, String>>{};
      for (final e in evs) {
        if (!seen.add(e.pubkey)) continue;
        final m = _profileMap(e.pubkey);
        if (m['name'] != null) {
          entries[e.pubkey] = m;
          _profSent.add(e.pubkey);
        }
        if (entries.length >= 4000) break;
      }
      if (entries.isNotEmpty) {
        toMain.send({'snap': 'profiles', 'entries': entries});
      }
    } catch (_) {}
  }

  void handle(Map<String, dynamic> c) {
    if (!_ok) return;
    try {
      switch (c['cmd']) {
        case 'addRelay':
          _hub.addRelay('${c['uri']}');
        case 'removeRelay':
          _hub.removeRelay('${c['uri']}');
        case 'subscribe':
          final subId = '${c['subId']}';
          _drainSubs.add(subId);
          _hub.subscribeWithId(subId, _filters(c['filters']));
        case 'discovery':
          final subId = '${c['subId']}';
          _drainSubs.add(subId);
          _hub.subscribeDiscoveryWithId(
            subId,
            minLikes: (c['minLikes'] as int?) ?? 2,
          );
        case 'firehose':
          final subId = '${c['subId']}';
          _drainSubs.add(subId);
          _hub.subscribeFirehoseWithId(
            subId,
            requireProfile: c['requireProfile'] != false,
          );
        case 'trusted':
          // Self + everyone we follow. They bypass the firehose quality gate —
          // you do not vet someone you chose to follow.
          _hub.trustedAuthors = {for (final p in (c['pubs'] as List)) '$p'};
        case 'muted':
          _hub.mutedAuthors = {for (final p in (c['pubs'] as List)) '$p'};
        case 'refreshBurst':
          final req = '${c['req']}';
          unawaited(
            _hub.refreshBurst(n: (c['n'] as int?) ?? 100).then((count) {
              toMain.send({
                'snap': 'refreshBurstDone',
                'req': req,
                'count': count,
              });
            }),
          );
        case 'resume':
          _hub.resumeNetwork();
        case 'backgroundTick':
          _hub.backgroundTick(nowMs: c['nowMs'] as int?);
        case 'resumeRefresh':
          final req = '${c['req']}';
          unawaited(
            _hub.resumeAndRefreshFirehose(n: (c['n'] as int?) ?? 100).then((
              count,
            ) {
              toMain.send({
                'snap': 'refreshBurstDone',
                'req': req,
                'count': count,
              });
            }),
          );
        case 'unsubscribe':
          _drainSubs.remove('${c['subId']}');
          _hub.unsubscribe('${c['subId']}');
        case 'publish':
          _hub.publish(
            NostrEvent.fromJson((c['event'] as Map).cast<String, dynamic>()),
          );
        case 'trackStats':
          _hub.trackStats((c['ids'] as List).cast<String>());
        case 'recordReaction':
          final pub = '${c['pub']}';
          selfPub ??= pub; // learn our pubkey so the mine-check works
          _hub.recordReaction('${c['id']}', pub);
        case 'relayEnable':
          _hub.setRelayEnabled('${c['uri']}', c['on'] == true);
        case 'selfPub':
          selfPub = '${c['pub']}';
          _hub.selfPubkey = selfPub;
        case 'recordVote':
          final pub = '${c['pub']}';
          selfPub ??= pub;
          _hub.recordVote('${c['id']}', pub, (c['vote'] as num).toInt());
        case 'fetchEvent':
          final id = '${c['id']}';
          final have = _hub.eventById(id);
          if (have != null) {
            toMain.send({'snap': 'event', 'id': id, 'event': have.toJson()});
          } else {
            _hub.fetchEvent(id); // ask the relays; it lands in the store
            _wantEvents.add(id);
          }
        case 'verify':
          // Events that arrived over Reticulum. RNS lives on the MAIN isolate,
          // and secp256k1 must not: verifying a mesh peer's batch there is the
          // pattern that froze the app for hours (docs/performance.md §3.1).
          // So the bytes come here, the signatures are checked on this isolate,
          // and only the survivors go back — where the caller stores them with
          // putAllVerified and never runs Schnorr itself.
          final reqId = '${c['req']}';
          final raw = (c['events'] as List?) ?? const [];
          final ok = <Map<String, dynamic>>[];
          for (final j in raw) {
            if (j is! Map) continue;
            try {
              final ev = NostrEvent.fromJson(j.cast<String, dynamic>());
              if (ev.verify()) ok.add(ev.toJson());
            } catch (_) {
              // A malformed event from a peer is not an error, it is a peer.
            }
          }
          toMain.send({'snap': 'verified', 'req': reqId, 'events': ok});
        case 'trackProfile':
          _hub.trackProfile('${c['pub']}');
        case 'fetchReplies':
          _sendReplies('${c['id']}');
        case 'close':
          _timer?.cancel();
      }
    } catch (_) {}
  }

  List<NostrFilter> _filters(dynamic raw) => [
    if (raw is List)
      for (final f in raw)
        if (f is Map) NostrFilter.fromJson(f.cast<String, dynamic>()),
  ];

  /// The NOSTR way to know who I follow: subscribe my own kind-3 contact list
  /// from the relays, parse its p-tags, and push the pubkeys to the main isolate
  /// (so follows made on ANY client show up here, not just local follows).
  // Our own contact list changes when a new kind-3 arrives — which is rare and
  // which the hub tells us about. Recomputing it on every 400ms tick meant a
  // sqlite query plus a re-parse of every p-tag (a contact list routinely has
  // thousands) 2.5 times a second, forever: a whole pegged core, for a value
  // that had not changed. The dedup guard below only ever suppressed the port
  // message, never the work. Gate on the STORED EVENT instead, and only re-read
  // when the hub has stored something new.
  int _myFollowsAt = 0; // createdAt of the kind-3 we last parsed
  bool _myFollowsDirty = true; // a new event landed — re-read on next tick

  void _syncMyFollows() {
    final me = selfPub;
    if (me == null || me.length != 64) return;
    if (!_myFollowsSub) {
      _myFollowsSub = true;
      _hub.subscribeWithId('myfollows', [
        NostrFilter(kinds: const [3], authors: [me]),
      ]);
    }
    if (!_myFollowsDirty) return; // nothing new since we last parsed
    _myFollowsDirty = false;

    NostrEvent? latest;
    for (final e in _store.query(
      NostrFilter(kinds: const [3], authors: [me]),
    )) {
      if (latest == null || e.createdAt > latest.createdAt) latest = e;
    }
    if (latest == null) return;
    if (latest.createdAt <= _myFollowsAt) return; // same list as last time
    _myFollowsAt = latest.createdAt;

    final pubs = <String>{};
    for (final t in latest.tags) {
      if (t.length >= 2 && t[0] == 'p' && t[1].length == 64) {
        pubs.add(t[1].toLowerCase());
      }
    }
    if (_myFollowsSent != null &&
        _myFollowsSent!.length == pubs.length &&
        _myFollowsSent!.containsAll(pubs)) {
      return; // unchanged
    }
    _myFollowsSent = pubs;
    toMain.send({'snap': 'myFollows', 'pubs': pubs.toList()});
  }

  // ── Cadence is a battery setting, not a freshness setting ────────────────
  //
  // The tick ran at 400ms unconditionally. On a phone with no network that is
  // 150 wake-ups a minute to drain subscriptions nothing is filling and to run
  // a whole-table sqlite join for notifications that cannot have changed —
  // measured at 98% of a core on a device with Bluetooth as its only interface,
  // with the log showing nothing but failed DNS lookups.
  //
  // So the fast cadence is earned: it applies while a relay socket is actually
  // up. With every relay down the engine drops to a slow beat, and the FIRST
  // thing that changes (a socket connecting) restores it immediately.
  static const Duration _tickFast = Duration(milliseconds: 400);
  static const Duration _tickIdle = Duration(seconds: 5);
  Duration _tickEvery = _tickFast;

  /// Something was stored since the last notifications join. Starts true so the
  /// first pass after launch always runs.
  bool _storedSinceNotif = true;

  void _scheduleTick() {
    _timer?.cancel();
    _timer = Timer.periodic(_tickEvery, (_) => _tick());
  }

  /// How long after the last inbound frame the fast cadence is still worth it.
  /// Generous: a live firehose delivers constantly, so this only expires when
  /// the network really has nothing for us.
  static const Duration _busyFor = Duration(seconds: 30);

  /// Move between the two cadences, paced by TRAFFIC rather than by socket
  /// state. "A relay is connected" was useless: the app hosts its own local
  /// relay, permanently connected and permanently silent, so a phone with no
  /// network still looked busy and kept the 400ms tick.
  void _retuneTick() {
    final busy = _hub.relayTrafficSince(_busyFor);
    final want = busy ? _tickFast : _tickIdle;
    if (want == _tickEvery) return;
    _tickEvery = want;
    _scheduleTick();
    toMain.send({
      'log': 'NOSTR: engine tick -> ${want.inMilliseconds}ms '
          '(${busy ? "frames arriving" : "no relay traffic for 30s"})',
    });
  }

  void _tick() {
    _tickN++;
    _retuneTick();
    // Relay statuses change on the order of seconds, not 400ms.
    if (_tickN % 5 == 0) {
      toMain.send({'snap': 'relays', 'json': _hub.relaysJson()});
    }

    _syncMyFollows();

    // Drained events per wapp-facing sub.
    for (final sub in _drainSubs) {
      final evs = _hub.drainEvents(sub, max: 60);
      if (evs.isNotEmpty) {
        // The hand-off the feed depends on. Silent here = the gate kept posts and
        // nobody ever saw them.
        toMain.send({'log': 'engine->main: sub=$sub n=${evs.length}'});
        toMain.send({'snap': 'events', 'subId': sub, 'events': evs});
      }
    }

    // Notifications, straight from the store — they outlive the process and the
    // network, which is the whole reason they are stored.
    //
    // EVERY 10 SECONDS, NOT EVERY TICK. This is a sqlite tag-join over the whole
    // events table, and at 400ms it owned the isolate's event loop: the relay
    // sockets live on this isolate, their handshakes and frames never got a turn,
    // and every websocket sat "connected" delivering nothing while a raw probe
    // on the main isolate streamed happily. The feed starved on a query whose
    // answer nobody needs faster than once in ten seconds.
    // …and only when something actually landed since the last run. The join is
    // over the whole events table; re-running it against an unchanged table is
    // the "work redone forever" pattern this file has been bitten by before.
    if (selfPub != null && _tickN % 25 == 0 && _storedSinceNotif) {
      _storedSinceNotif = false;
      final notifs = _hub.myNotifications(limit: 100);
      final sig = notifs.isEmpty ? '' : '${notifs.length}:${notifs.first.id}';
      if (sig != _notifSig) {
        _notifSig = sig;
        toMain.send({
          'snap': 'notifications',
          'events': [for (final e in notifs) e.toJson()],
        });
      }
    }

    // Events the main isolate asked for (a notification's post, say) that have
    // since arrived from a relay.
    if (_wantEvents.isNotEmpty) {
      for (final id in _wantEvents.toList()) {
        final e = _hub.eventById(id);
        if (e == null) continue;
        _wantEvents.remove(id);
        toMain.send({'snap': 'event', 'id': id, 'event': e.toJson()});
      }
    }

    // Inbound-event rates — the firehose is this isolate's whole CPU cost.
    final ev = _hub.drainEventStats();
    if (ev.values.any((v) => v > 0)) {
      toMain.send({'snap': 'evstats', 'stats': ev});
    }

    // What the quality gate kept, held and dropped, by reason. Without this,
    // "the All tab looks empty" is unanswerable except by guesswork.
    // Compute it ONLY when we are about to log it: relayHealth() drains the
    // frame counters, so calling it every 400ms tick and printing every 30th
    // reported the last 400ms and always said zero. The reporter must not eat
    // the evidence it is reporting.
    if (_healthTick++ % 75 == 0) {
      final health = _hub.relayHealth();
      if (health.isNotEmpty) toMain.send({'log': 'relays: $health'});
    }

    final fh = _hub.drainFirehoseStats();
    if (fh.values.any((v) => v > 0)) {
      toMain.send({'snap': 'fhstats', 'stats': fh});
    }

    // Changed engagement stats.
    final statEntries = <String, List<Object>>{};
    for (final id in _hub.trackedStatIds) {
      final s = _hub.statsOf(id, selfPub);
      final v = _hub.votesOf(id, selfPub);
      final prev = _statsSent[id];
      final now = (s.$1, s.$2, s.$3, v.$1, v.$2, v.$3);
      if (prev == null || prev != now) {
        _statsSent[id] = now;
        statEntries[id] = [s.$1, s.$2, s.$3, v.$1, v.$2, v.$3];
      }
    }
    if (statEntries.isNotEmpty) {
      toMain.send({'snap': 'stats', 'entries': statEntries});
    }

    // New profiles.
    //
    // A MISS must be remembered, not just a hit. _profSent only records pubkeys
    // whose kind-0 we found, so every author we've seen but whose profile never
    // arrives (most of a public firehose) was re-queried against sqlite on
    // EVERY 400ms tick, forever — hundreds of queries a second, no events, one
    // core pegged. Re-check a miss only occasionally: the profile can still
    // show up later, but it costs one query per pubkey per window, not 150.
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    final profEntries = <String, Map<String, String>>{};
    var looked = 0;
    for (final pub in _hub.trackedProfilePubs) {
      if (_profSent.contains(pub)) continue;
      final retryAt = _profMissAt[pub];
      if (retryAt != null && nowMs - retryAt < _profMissRetryMs) continue;
      // Bound the work of any single tick, so a big backlog is spread out
      // instead of stalling the engine in one go.
      if (looked >= _profLookupsPerTick) break;
      looked++;
      final p = _profileMap(pub);
      if (p.isNotEmpty && p['name'] != null) {
        _profSent.add(pub);
        _profMissAt.remove(pub);
        profEntries[pub] = p;
      } else {
        _profMissAt[pub] = nowMs;
      }
    }
    if (profEntries.isNotEmpty) {
      toMain.send({'snap': 'profiles', 'entries': profEntries});
    }
  }

  // pubkey -> when we last looked for its (absent) kind-0 profile.
  final Map<String, int> _profMissAt = {};
  static const int _profMissRetryMs = 5 * 60 * 1000;
  static const int _profLookupsPerTick = 8;

  void _sendReplies(String postId) {
    final out = [
      for (final e in _hub.repliesTo(postId))
        {
          'id': e.id ?? '',
          'pubkey': e.pubkey,
          'content': e.content,
          'ts': e.createdAt,
        },
    ];
    toMain.send({'snap': 'replies', 'id': postId, 'events': out});
  }

  Map<String, String> _profileMap(String pub) {
    final ev = _hub.profileOf(pub);
    final out = <String, String>{};
    try {
      out['npub'] = NostrCrypto.encodeNpub(pub);
    } catch (_) {}
    if (ev == null) return out;
    try {
      final j = jsonDecode(ev.content);
      if (j is Map) {
        String s(String k) => (j[k] ?? '').toString().trim();
        final name = s('display_name').isNotEmpty
            ? s('display_name')
            : (s('displayName').isNotEmpty ? s('displayName') : s('name'));
        if (name.isNotEmpty) out['name'] = name;
        if (s('picture').startsWith('http')) out['pic'] = s('picture');
        if (s('about').isNotEmpty) out['about'] = s('about');
        if (s('nip05').isNotEmpty) out['nip05'] = s('nip05');
        if (s('website').isNotEmpty) out['website'] = s('website');
        final lud = s('lud16').isNotEmpty ? s('lud16') : s('lud06');
        if (lud.isNotEmpty) out['lud16'] = lud;
        if (s('banner').startsWith('http')) out['banner'] = s('banner');
      }
    } catch (_) {}
    return out;
  }
}
