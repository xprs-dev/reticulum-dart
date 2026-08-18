/*
 * DhtNode — the Kademlia engine: a routing table, a local record store, and the
 * iterative FIND_NODE / FIND_VALUE / STORE algorithms plus publish() and
 * resolve(). Transport-agnostic: the owner supplies [sendRpc] (send a DhtMessage
 * to a contact, await the reply) — in-process for tests, or over a Reticulum link
 * in the live node. handle()/handleEncoded() implement the responder side.
 *
 * resolve(sha256) is what an edge client's entry node runs on its behalf:
 * recursively walk to the nodes closest to the file key, collecting verified,
 * unexpired provider records, ranked by capacity class (best providers first).
 */
import 'dart:async';
import 'dart:typed_data';

import '../../reticulum/rns_identity.dart';
import 'dht_core.dart';
import 'dht_message.dart';
import 'holder_hint.dart';
import 'provider_record.dart';
import 'routing_table.dart';

/// Send a DHT message to [to] and await the reply (null on failure/timeout).
typedef DhtRpc = Future<DhtMessage?> Function(DhtContact to, DhtMessage req);

class DhtNode {
  final RnsIdentity identity; // full identity (private) — to sign nothing here,
  // but it identifies us; records are signed by the provider, not the DHT node.
  final int k;
  final int alpha;
  final DhtRpc sendRpc;
  final void Function(String msg)? log;

  /// Optional persistence anchors: a small, stable set of always-on holders
  /// (e.g. the relay indexers) that we additionally STORE to and query FIRST on
  /// resolve, regardless of XOR distance. Records thus survive churn of the
  /// ephemeral k-closest, and stay findable even when k is small — the XOR-walk
  /// becomes a fallback. Supplied by the owner (the DHT engine stays generic);
  /// empty/unset → classic Kademlia behaviour.
  final List<DhtContact> Function()? anchors;

  /// What we can say about a holder when we hand it out: its power, uplink and
  /// radios, and how recently we heard of it. The DHT itself knows none of that
  /// — the HOST does (it owns the relay directory and the announces) — so it
  /// supplies this, and we stay transport- and app-agnostic. Without it we still
  /// report freshness, which is the signal a caller needs most.
  HolderHint? Function(Uint8List providerPub)? hintProvider;

  /// When we last had evidence of a (provider, key) pair: the STORE that carried
  /// it, or a refresh. Feeds the freshness half of a hint — a holder last heard
  /// of three weeks ago is a lottery ticket, and a caller deserves to know
  /// before it spends a link on one.
  final Map<String, int> _acceptedAt = {};

  /// Anti-abuse ceilings on the local record store. Routing DHT RPC over the
  /// (widely-known) chat dest means any peer can open a link and STORE at us, so
  /// we bound how much they can make us hold: at most [maxStoredKeys] distinct
  /// keys, and [maxRecordsPerKey] providers per key. A STORE that would exceed
  /// either is rejected BEFORE the expensive signature verify, so a flood can't
  /// burn CPU or memory once we're full. Worst-case memory is the product of the
  /// two — sized to a safe ceiling, far above normal use.
  final int maxStoredKeys;
  final int maxRecordsPerKey;

  /// FIND_VALUE requests this node answered WITH RECORDS — the "is my offer
  /// being used at all" number an Indexer's owner reads off the dashboard.
  /// Lifetime total; the host samples deltas into an hourly ring for the rate.
  int queriesAnswered = 0;

  /// STOREs refused by the caps above (observability).
  int storesRejected = 0;

  late final Uint8List myId = DhtContact.ofIdentity(identity).id;
  late final Uint8List myPub = identity.getPublicKey();
  late final RoutingTable routing = RoutingTable(myId, k: k);

  // fileKey(16B) hex -> provider records this node custodies.
  final Map<String, List<ProviderRecord>> _store = {};

  DhtNode({
    required this.identity,
    this.k = 8,
    this.alpha = 3,
    required this.sendRpc,
    this.log,
    this.maxStoredKeys = 10000,
    this.maxRecordsPerKey = 24,
    this.anchors,
  });

  /// Anchor contacts to also reach this round, excluding ourselves and anything
  /// already in [exclude] (the k-closest), deduped by id.
  List<DhtContact> _anchorsExcluding(Set<String> exclude) {
    final list = anchors?.call();
    if (list == null || list.isEmpty) return const [];
    final out = <DhtContact>[];
    final seen = <String>{...exclude};
    for (final c in list) {
      if (dhtIdEquals(c.id, myId)) continue;
      if (seen.add(c.idHex)) out.add(c);
    }
    return out;
  }

  int get storedKeys => _store.length;

  /// How many provider records we have accepted from OTHER nodes (replicas) —
  /// the live signal that replication is actually landing on this node, as
  /// opposed to records we published about our own content.
  int replicasStored = 0;

  /// How many provider records we have dropped because a fetch from that provider
  /// failed (dead-holder pruning) — the counterpart to contact eviction.
  int providersDemoted = 0;

  // ── Responder side ───────────────────────────────────────────────────────
  Future<DhtMessage> handle(DhtMessage req,
      {int? maxContacts, int? maxRecords}) async {
    // Reply sizes default to the one-small-packet caps, but the transport can
    // raise them to fit a larger negotiated link MTU (fewer rounds on wide
    // lookups). See file_node._onDhtServePacket.
    final maxC = maxContacts ?? kDhtWireMaxContacts;
    final maxR = maxRecords ?? kDhtWireMaxRecords;
    routing.add(req.sender); // learn whoever contacts us
    switch (req.op) {
      case DhtOp.ping:
        return DhtMessage.pong(myPub);
      case DhtOp.findNode:
        return DhtMessage.nodes(
            myPub, _cap(routing.closest(req.target!, k), maxC));
      case DhtOp.findValue:
        final key = dhtFileKey(req.sha!);
        final recs = _liveRecords(key, req.sha!);
        if (recs.isEmpty) {
          return DhtMessage.valueNodes(
              myPub, _cap(routing.closest(key, k), maxC));
        }
        queriesAnswered++;
        // "These N devices have it" — and what we know about each, so the caller
        // does not have to guess which one to wake (docs/NOSTR.md).
        final capped = _cap(recs, maxR);
        return DhtMessage.valueRecords(
          myPub,
          capped,
          hints: [for (final r in capped) _hintFor(r)],
        );
      case DhtOp.store:
        final r = req.records.first;
        // Anti-abuse: refuse over-cap STOREs BEFORE the signature verify so a
        // flood can't burn CPU/memory once we're full.
        if (!_admitStore(r)) {
          storesRejected++;
          return DhtMessage.storeOk(myPub, false);
        }
        final ok = await _accept(r);
        if (ok && !_eq(r.providerPub, myPub)) {
          replicasStored++;
          log?.call('stored replica ${dhtHex(r.sha256).substring(0, 8)} from '
              '${dhtHex(r.providerPub).substring(0, 8)} (replication landed)');
        }
        return DhtMessage.storeOk(myPub, ok);
      default:
        return DhtMessage.pong(myPub);
    }
  }

  /// Wire entry point for the live transport.
  Future<Uint8List?> handleEncoded(Uint8List raw,
      {int? maxContacts, int? maxRecords}) async {
    final m = DhtMessage.decode(raw);
    if (m == null) return null;
    return (await handle(m, maxContacts: maxContacts, maxRecords: maxRecords))
        .encode();
  }

  // ── Initiator side ─────────────────────────────────────────────────────────
  /// Seed the routing table and warm it by looking ourselves up.
  Future<void> bootstrap(List<DhtContact> seeds) async {
    for (final s in seeds) {
      routing.add(s);
    }
    await iterativeFindNode(myId);
  }

  /// Enough confirmed replicas for solid redundancy. Once this many peers ACK a
  /// STORE, publish() returns without waiting for the rest to answer (or to time
  /// out) — k is sized to cover the whole overlay (most of which is unreachable
  /// or slow), so waiting for all of them just stalled publish and undercounted.
  static const int targetReplicas = 8;

  /// Publish a signed provider record at the nodes closest to its file key.
  /// Returns how many peers CONFIRMED storing it (plus self).
  Future<int> publish(ProviderRecord r) async {
    final closestNodes = await iterativeFindNode(r.fileKey);
    // Also STORE to the persistence anchors (always-on holders), deduped against
    // the k-closest — records survive churn of the ephemeral closest set, and a
    // resolver reaches them via the anchors-first path regardless of distance/k.
    final closest = [
      ...closestNodes,
      ..._anchorsExcluding({for (final c in closestNodes) c.idHex}),
    ];
    // Fan the STOREs out concurrently, but return as soon as [targetReplicas]
    // peers have ACKed — don't block on the long tail. Two reasons this matters:
    // (a) the k-closest is most of the overlay, much of it unreachable/slow, so
    // waiting for every STORE to answer-or-time-out stalled publish for the full
    // RPC timeout on each dead-but-routable contact; (b) a STORE ACK arrives a
    // full extra round-trip after the data is already stored, so under the old
    // tight wait the ACKs landed AFTER we'd given up — publish logged
    // "1 holders" even though replication had succeeded. The in-flight STOREs we
    // don't wait for still complete in the background and still land their
    // records (more replicas = better); we just stop COUNTING once we have enough.
    var ok = 0;
    final enough = Completer<void>();
    var pending = closest.length;
    for (final c in closest) {
      // Detached on purpose: survives past the early return to keep replicating.
      // ignore: discarded_futures
      () async {
        routing.add(c);
        final resp = await sendRpc(c, DhtMessage.store(myPub, r));
        if (resp != null && resp.op == DhtOp.storeOk && resp.ok) {
          if (++ok >= targetReplicas && !enough.isCompleted) enough.complete();
        }
        if (--pending == 0 && !enough.isCompleted) enough.complete();
      }();
    }
    if (closest.isNotEmpty) await enough.future;
    // ALWAYS keep our own record locally: we are authoritative for content we
    // hold, so a resolver that queries us (we're in its routing) must get it even
    // if every replication STORE to the k-closest failed. Previously we stored
    // locally only when isolated (closest.isEmpty), so a publisher with peers but
    // flaky paths replicated to nobody AND kept nothing — its file became
    // undiscoverable despite it sitting right there. That was the root cause of
    // "resolved 0 providers" between two meshed devices.
    final keptSelf = await _accept(r);
    final confirmed = ok; // peers that ACKed by the time we returned
    if (keptSelf && ok == 0) ok = 1;
    log?.call('publish ${dhtHex(r.sha256).substring(0, 8)} -> $confirmed peer '
        'replica(s)${keptSelf ? ' +self' : ''}');
    return ok;
  }

  /// Resolve a file id to its providers (verified, unexpired), best class first.
  /// The hints that came back with the last [resolve] — keyed by provider pubkey
  /// hex. A caller ranks holders with these (see rankHolders); they are advisory,
  /// and a provider that then fails to serve is demoted regardless.
  final Map<String, HolderHint> lastHints = {};

  Future<List<ProviderRecord>> resolve(Uint8List sha256) async {
    final target = dhtFileKey(sha256);
    lastHints.clear();
    final found = <String, ProviderRecord>{}; // providerPub hex -> record
    for (final r in _liveRecords(target, sha256)) {
      found[dhtHex(r.providerPub)] = r;
    }
    // Anchors-first fast path: query the always-on holders directly (regardless
    // of XOR distance), in parallel. publish() stores to them, so for most keys a
    // verified record is here in one round — and it stays findable even if k is
    // small. Only fall through to the XOR-walk when the anchors don't have it.
    final anchorContacts = _anchorsExcluding(const {});
    if (anchorContacts.isNotEmpty) {
      await Future.wait(anchorContacts.map((c) async {
        final resp = await sendRpc(c, DhtMessage.findValue(myPub, sha256));
        if (resp == null || !resp.hasValue) return;
        routing.add(c);
        for (var idx = 0; idx < resp.records.length; idx++) {
          final r = resp.records[idx];
          if (!_eq(r.sha256, sha256) || r.isExpired()) continue;
          if (!await r.verify()) continue;
          found[dhtHex(r.providerPub)] = r;
          if (idx < resp.hints.length) {
            lastHints[dhtHex(r.providerPub)] = resp.hints[idx];
          }
        }
      }));
      if (found.isNotEmpty) {
        return found.values.toList()
          ..sort((a, b) => a.capacity.compareTo(b.capacity));
      }
    }
    await _iterate(
      target,
      makeReq: () => DhtMessage.findValue(myPub, sha256),
      onResponse: (resp) async {
        if (!resp.hasValue) return;
        for (var idx = 0; idx < resp.records.length; idx++) {
          final r = resp.records[idx];
          if (!_eq(r.sha256, sha256) || r.isExpired()) continue;
          if (!await r.verify()) continue;
          found[dhtHex(r.providerPub)] = r;
          if (idx < resp.hints.length) {
            lastHints[dhtHex(r.providerPub)] = resp.hints[idx];
          }
        }
      },
      // FIND_VALUE short-circuits: the moment a queried node returns a verified
      // record, stop the lookup. Without this, resolve ground through all k
      // contacts (8 s timeout each) even after the value was in hand on round 1
      // — the cause of the multi-minute "check for updates" hang when most
      // contacts were stale. We still keep the whole round that found it, so a
      // resolver gets several providers (redundancy), not just the first.
      stopEarly: () => found.isNotEmpty,
    );
    final list = found.values.toList()
      ..sort((a, b) => a.capacity.compareTo(b.capacity));
    return list;
  }

  /// What we can honestly say about the holder of [r]: how recently we had
  /// evidence of it, whether that evidence is first-hand, and what it is made
  /// of. The host supplies [hintProvider] (it owns the relay directory and the
  /// announces); with none, we still report freshness, which is the signal a
  /// caller needs most.
  HolderHint _hintFor(ProviderRecord r) {
    final fromHost = hintProvider?.call(r.providerPub);
    if (fromHost != null) return fromHost;
    final acceptedMs = _acceptedAt[dhtHex(r.providerPub) + dhtHex(r.sha256)];
    final ageSec = acceptedMs == null
        ? 0xffff
        : ((DateTime.now().millisecondsSinceEpoch - acceptedMs) ~/ 1000);
    return HolderHint(lastHeardSec: ageSec, source: HintSource.direct);
  }

  /// Find the k contacts closest to [target] (iterative).
  Future<List<DhtContact>> iterativeFindNode(Uint8List target) async {
    final shortlist = await _iterate(target, makeReq: null, onResponse: null);
    return shortlist;
  }

  /// Core iterative lookup. With [makeReq]/[onResponse] it does FIND_VALUE
  /// (collecting via onResponse), else FIND_NODE. Returns the k closest contacts
  /// discovered.
  Future<List<DhtContact>> _iterate(
    Uint8List target, {
    DhtMessage Function()? makeReq,
    Future<void> Function(DhtMessage resp)? onResponse,
    bool Function()? stopEarly,
  }) async {
    final shortlist = <String, DhtContact>{};
    for (final c in routing.closest(target, k)) {
      shortlist[c.idHex] = c;
    }
    final queried = <String>{};
    final failed = <String>{};
    int cmp(DhtContact a, DhtContact b) =>
        dhtCompare(dhtXor(a.id, target), dhtXor(b.id, target));

    for (var round = 0; round < 24; round++) {
      final candidates = shortlist.values
          .where((c) => !queried.contains(c.idHex) && !failed.contains(c.idHex))
          .toList()
        ..sort(cmp);
      if (candidates.isEmpty) break;
      final batch = candidates.take(alpha).toList();
      final results = await Future.wait(batch.map((c) async {
        queried.add(c.idHex);
        final req = makeReq != null
            ? makeReq()
            : DhtMessage.findNode(myPub, target);
        final resp = await sendRpc(c, req);
        return MapEntry(c, resp);
      }));
      var improved = false;
      for (final e in results) {
        final resp = e.value;
        if (resp == null) {
          failed.add(e.key.idHex);
          continue;
        }
        routing.add(e.key);
        if (onResponse != null) await onResponse(resp);
        for (final nc in resp.contacts) {
          if (dhtIdEquals(nc.id, myId)) continue;
          routing.add(nc);
          if (!shortlist.containsKey(nc.idHex)) {
            shortlist[nc.idHex] = nc;
            improved = true;
          }
        }
      }
      // FIND_VALUE early termination: the value was found this round, stop now
      // rather than walking the rest of the (possibly stale, slow) shortlist.
      if (stopEarly?.call() ?? false) break;
      final top = (shortlist.values.toList()..sort(cmp)).take(k);
      if (top.every((c) => queried.contains(c.idHex) || failed.contains(c.idHex))) {
        break;
      }
      if (!improved && batch.length < alpha) break;
    }
    final out = shortlist.values.toList()..sort(cmp);
    return out.take(k).toList();
  }

  // ── Local store ────────────────────────────────────────────────────────────

  /// Cheap (no-verify) admission gate for an incoming STORE. A refresh of a
  /// record we already hold for this (key, provider) never grows the store and is
  /// always allowed; otherwise the new key must fit under [maxStoredKeys] and the
  /// existing key under [maxRecordsPerKey]. Uses only list/map sizes, so it is
  /// drift-free (always accurate) and runs before the Ed25519 verify in _accept.
  bool _admitStore(ProviderRecord r) {
    final list = _store[dhtHex(r.fileKey)];
    if (list == null) return _store.length < maxStoredKeys; // a brand-new key
    if (list.any((e) => _eq(e.providerPub, r.providerPub))) return true; // refresh
    return list.length < maxRecordsPerKey;
  }

  /// Accept a record into the local map WITHOUT it having come over an RPC —
  /// the door an indexer sync comes through. It runs the same anti-abuse cap and
  /// the same signature verify as a STORE, because a pointer handed to us by a
  /// peer deserves exactly as much trust as one shouted at us by a stranger:
  /// none.
  Future<bool> storeLocal(ProviderRecord r) async {
    if (!_admitStore(r)) {
      storesRejected++;
      return false;
    }
    return _accept(r);
  }

  Future<bool> _accept(ProviderRecord r) async {
    if (r.isExpired()) return false;
    if (!await r.verify()) return false;
    final key = dhtHex(r.fileKey);
    final list = _store.putIfAbsent(key, () => <ProviderRecord>[]);
    list.removeWhere((e) => _eq(e.providerPub, r.providerPub));
    list.add(r);
    _acceptedAt[dhtHex(r.providerPub) + dhtHex(r.sha256)] =
        DateTime.now().millisecondsSinceEpoch;
    // Bounded like everything else here: a flood must not turn this into a leak.
    if (_acceptedAt.length > maxStoredKeys * 4) {
      final drop = _acceptedAt.keys.take(_acceptedAt.length ~/ 4).toList();
      for (final d in drop) {
        _acceptedAt.remove(d);
      }
    }
    return true;
  }

  /// How old the held pointers are: counts for <1h / <24h / <7d / older.
  ///
  /// Age = when WE last had evidence of the record (`_acceptedAt`), falling back
  /// to the record's own timestamp. One walk over the store — cheap at the
  /// 10k-key cap, and it is what makes "remove older than X" an informed act
  /// instead of a guess.
  ({int h1, int d1, int d7, int older}) ageBuckets({int? nowMs}) {
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    var h1 = 0, d1 = 0, d7 = 0, older = 0;
    for (final list in _store.values) {
      for (final r in list) {
        final at = _acceptedAt[dhtHex(r.providerPub) + dhtHex(r.sha256)] ??
            r.timestampMs;
        final age = now - at;
        if (age < 3600000) {
          h1++;
        } else if (age < 86400000) {
          d1++;
        } else if (age < 7 * 86400000) {
          d7++;
        } else {
          older++;
        }
      }
    }
    return (h1: h1, d1: d1, d7: d7, older: older);
  }

  /// Remove (or, with [dryRun], count) every record older than [age].
  ///
  /// Preview first: a cleanup tool that cannot tell you what it is about to
  /// delete is not a tool, it is a gamble. Returns the records affected and, via
  /// [onRemoved], hands each real removal to the caller — who is expected to put
  /// it in the pointer log so the deletion TRAVELS to synced indexers (a dead
  /// address must propagate as surely as a new one).
  int sweepOlderThan(
    Duration age, {
    bool dryRun = false,
    int? nowMs,
    void Function(ProviderRecord record)? onRemoved,
  }) {
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    final cutoff = now - age.inMilliseconds;
    var n = 0;
    final emptyKeys = <String>[];
    for (final e in _store.entries) {
      final victims = <ProviderRecord>[];
      for (final r in e.value) {
        final at = _acceptedAt[dhtHex(r.providerPub) + dhtHex(r.sha256)] ??
            r.timestampMs;
        if (at < cutoff) victims.add(r);
      }
      n += victims.length;
      if (dryRun) continue;
      for (final r in victims) {
        e.value.remove(r);
        _acceptedAt.remove(dhtHex(r.providerPub) + dhtHex(r.sha256));
        onRemoved?.call(r);
      }
      if (e.value.isEmpty) emptyKeys.add(e.key);
    }
    for (final k in emptyKeys) {
      _store.remove(k);
    }
    return n;
  }

  /// Remove (or count) every record from one provider, across ALL keys —
  /// `demoteProvider` is per-key; this is the "evict this depositor" tool.
  int dropProviderEverywhere(
    Uint8List providerPub, {
    bool dryRun = false,
    void Function(ProviderRecord record)? onRemoved,
  }) {
    final pub = dhtHex(providerPub);
    var n = 0;
    final emptyKeys = <String>[];
    for (final e in _store.entries) {
      final victims = [
        for (final r in e.value)
          if (dhtHex(r.providerPub) == pub) r
      ];
      n += victims.length;
      if (dryRun) continue;
      for (final r in victims) {
        e.value.remove(r);
        _acceptedAt.remove(pub + dhtHex(r.sha256));
        onRemoved?.call(r);
      }
      if (e.value.isEmpty) emptyKeys.add(e.key);
    }
    for (final k in emptyKeys) {
      _store.remove(k);
    }
    if (!dryRun && n > 0) providersDemoted += n;
    return n;
  }

  /// Drop a provider's record for [sha256] from our local store — called when a
  /// fetch from that provider FAILED, so neither we (next resolve) nor a peer
  /// querying us hands out a dead holder again. The provider re-publishes (every
  /// ~30 min) to come back, so a transient failure self-heals. Returns true if a
  /// record was actually removed.
  bool demoteProvider(Uint8List sha256, Uint8List providerPub) {
    final key = dhtHex(dhtFileKey(sha256));
    final list = _store[key];
    if (list == null) return false;
    final before = list.length;
    list.removeWhere((r) => _eq(r.providerPub, providerPub));
    if (list.isEmpty) _store.remove(key);
    final removed = list.length < before;
    if (removed) providersDemoted++;
    return removed;
  }

  List<ProviderRecord> _liveRecords(Uint8List fileKey16, Uint8List sha256) {
    final key = dhtHex(fileKey16);
    final list = _store[key];
    if (list == null) return const [];
    list.removeWhere((r) => r.isExpired());
    if (list.isEmpty) {
      _store.remove(key);
      return const [];
    }
    return list.where((r) => _eq(r.sha256, sha256)).toList();
  }

  // Cap a list so a NODES/VALUE response fits one ~450B link-encrypted packet
  // (no per-RPC fragmentation needed). Routing still uses the full k internally.
  static List<T> _cap<T>(List<T> xs, int n) =>
      xs.length <= n ? xs : xs.sublist(0, n);

  static bool _eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
