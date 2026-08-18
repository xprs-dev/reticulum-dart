/*
 * RelayNode — a NOSTR relay/indexer endpoint on the Dart Reticulum stack.
 *
 * Registers a 'geogram'/['relay'] destination and answers relay requests over an
 * RnsLink (responder side): EVENT publishes an event into the local
 * [RelayEventStore], REQ runs a NIP-01 filter (incl. NIP-50 search) and returns
 * the matches, COUNT returns a tally. As a client (initiator side) it can
 * publish/query/count against another relay's identity.
 *
 * Transport-agnostic like FileTransferNode / LxmfRouter: the owner supplies
 * [send] (e.g. transport.sendOnAll) and [nextHopFor] (transport addressing for
 * routed peers). Request and response each ride the link as a single encrypted
 * packet when small, else as an RNS Resource — the shared [_RelayLink] session
 * demuxes both directions by packet context (only one transfer is in flight at a
 * time in a request/response exchange, so contexts never collide).
 */
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../reticulum/rns_crypto.dart';
import '../reticulum/rns_identity.dart';
import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import '../reticulum/rns_resource.dart';
import '../reticulum/rns_resource_receiver.dart';
import '../reticulum/lxmf/lxmf.dart';
import '../reticulum/lxmf/lxmf_message.dart';
import '../reticulum/lxmf/lxmf_router.dart';
import '../../util/nostr_event.dart';
import '../../util/nostr_crypto.dart';
import 'relay_event_store.dart';
import '../files/dht/pointer_sync.dart';
import 'relay_protocol.dart';
import '../../util/npd.dart';
import 'spam.dart';

const String kRelayApp = 'geogram';
const List<String> kRelayAspects = ['relay'];

/// 1-byte type tag for relay RPC frames when they share a destination with the
/// DHT (the chat dest). DHT frames are tag 0x01 (file_node); relay is 0x02. Lets
/// the host that owns the shared link demux frames to the right tenant.
const int kRelayRpcTag = 0x02;

// Max relay message we send as a single link packet (else an RNS Resource).
const int _pktMax = 360;

class RelayNode {
  final RnsIdentity identity;
  final RelayEventStore store;
  final void Function(Uint8List raw) send;
  final Uint8List? Function(RnsIdentity peer)? nextHopFor;
  /// Per-destination next-hop + path-exists (Reticulum routes per-destination;
  /// see RnsLink.ensurePath). Prefer these over [nextHopFor].
  final Uint8List? Function(Uint8List destHash)? nextHopForDest;
  final bool Function(Uint8List destHash)? hasPathForDest;
  /// Pull a transport path to a peer we know by identity but have no cached route
  /// to (its announce was never flooded to us on busy hubs), so a relay query
  /// link is routable. See FileTransferNode.requestPath.
  final void Function(Uint8List destHash)? requestPath;
  final void Function(String msg)? log;

  /// Ask [peer] a query WITHOUT a link, via a connectionless NOSTR probe.
  ///
  /// Supplied by the host, which owns the NOSTR keys and the PLAIN transport, so
  /// this library stays free of app concepts. Tri-state on purpose:
  ///   supported=false          -> peer is an older node; use a link
  ///   supported=true, body=null-> the peer answered with SILENCE: it holds
  ///                               nothing. Do NOT open a link — that is the
  ///                               entire saving.
  ///   supported=true, body!=null-> a RESULT (or a HAVE hint, if too big)
  ///
  /// Distinguishing "has nothing" from "cannot probe" is what keeps the win on
  /// the querier's side too; collapsing them would send us back to a link on
  /// every empty query.
  final Future<({bool supported, Uint8List? body})> Function(
      RnsIdentity peer, Uint8List reqBytes)? probeQuery;

  /// Optional anti-spam acceptance policy applied to inbound EVENTs (PoW / rate
  /// / size). Null = accept anything with a valid signature.
  final SpamPolicy? spam;

  /// Whether to act as a relay SERVER (accept inbound links and answer
  /// EVENT/REQ/COUNT from the network). A phone/leaf sets this false: it still
  /// queries other relays (the client API below), but never serves the network
  /// — serving the whole network's queries off the device store pegged the UI
  /// isolate (57 MB/s of sqlite reads) and ANR'd the app. Mutable so the owner
  /// can flip hosting on/off at runtime (capacity / settings switch).
  bool serve;

  /// Queries served over links (REQ + COUNT) and probes answered — lifetime
  /// totals; the host samples deltas into an hourly ring for the dashboard's
  /// requests-per-hour. A role nobody can inspect is a role nobody trusts.
  int reqsServed = 0;
  int probesAnswered = 0;

  /// The pointer map this node syncs with other indexers (docs/NOSTR.md).
  ///
  /// Set by the host on an INDEXER; null on a leaf, and that is the point:
  /// battery-powered leaves announce, are indexed, and are left alone. Indexer-
  /// to-indexer traffic is fast and wired, so the load belongs there. A node
  /// with none simply answers SYNC_RESET with an empty epoch, which an asker
  /// reads as "this peer has no map to give".
  PointerSyncServer? pointerServer;

  /// Hosting tier classifier: maps an author pubkey (hex) to a retention tier
  /// index (0 self / 1 followed / 2 stranger). Null = treat everyone as stranger.
  int Function(String pubHex)? tierOfPub;

  /// Hosting admission gate for inbound EVENTs: returns a rejection reason, or
  /// null to accept. Null hook = accept (subject only to spam). Lets the owner
  /// enforce per-tier quotas without coupling the relay to the policy.
  String? Function(NostrEvent ev, int tier)? admitEvent;

  /// Called whenever an event is accepted via an inbound EVENT (so the owner can
  /// fan it out / re-index). Optional.
  void Function(NostrEvent event)? onEvent;

  late final Uint8List relayDestHash =
      RnsDestination.hash(identity, kRelayApp, kRelayAspects);

  /// The destination relay RPC links (REQ/EVENT/COUNT/SYNC) ride over. Defaults
  /// to the dedicated geogram/relay dest, but the host can point it at a more
  /// reliably-announced destination (e.g. the chat dest) so links route where
  /// transport paths actually exist — public hubs rate-limit and drop the
  /// dedicated geogram/relay announce, leaving peers with no path to it, so every
  /// REQ/sync link handshake times out ("0 answered"). The relay IDENTITY and
  /// [relayDestHash] are unaffected: they still classify the role and key the
  /// pointer log locally, needing no path. Mirrors FileTransferNode.rpcApp.
  final String rpcApp;
  final List<String> rpcAspects;
  late final Uint8List rpcDestHash =
      RnsDestination.hash(identity, rpcApp, rpcAspects);

  /// When the RPC dest is SHARED with another tenant (the DHT owns the chat dest
  /// and accepts its links first), our link frames must carry a 1-byte type tag
  /// so the host can demux them to us. Null = dedicated dest, no tag. Aurora sets
  /// [kRelayRpcTag]. The tag rides only OUR outbound requests + their responses;
  /// the local relay-dest path ([_serve]) stays untagged for back-compat.
  final int? rpcTag;

  final Map<String, _RelayLink> _in = {}; // responder links by link-id hex
  final Map<String, _Pending> _out = {}; // initiator requests by link-id hex
  int _subSeq = 0;

  /// Our own NOSTR pubkey (hex). When [serve] is false (a phone/leaf that won't
  /// host the whole network) the node still answers queries for ITS OWN posts —
  /// this returns that pubkey so the responder can scope a leaf's REQ to
  /// self-authored events. Null disables even self-serving.
  String? Function()? selfPubHex;

  RelayNode({
    required this.identity,
    required this.store,
    required this.send,
    this.nextHopFor,
    this.nextHopForDest,
    this.hasPathForDest,
    this.requestPath,
    this.spam,
    this.onEvent,
    this.log,
    this.serve = true,
    this.tierOfPub,
    this.admitEvent,
    this.selfPubHex,
    this.probeQuery,
    // Default to the dedicated relay dest (back-compat); Aurora overrides these
    // to the chat dest so links route where paths actually exist.
    this.rpcApp = kRelayApp,
    this.rpcAspects = kRelayAspects,
    this.rpcTag,
  });

  /// Feed an inbound packet; true if it belonged to the relay.
  /// True when this node will answer at least its OWN posts to a querier — i.e.
  /// it serves the whole network ([serve]) OR it can scope to self-authored
  /// events (a leaf with a known self pubkey). Lets a phone share what it
  /// posted without hosting the network ("ask the poster for its posts").
  bool get _answersQueries => serve || (selfPubHex?.call() != null);

  Future<bool> handlePacket(RnsPacket p) async {
    // Order matters: the cheap packet-type + dest-hash checks gate the call to
    // [_answersQueries], which may do real work (resolving our pubkey). Putting
    // them first keeps this O(1) for the flood of unrelated packets on a busy
    // hub — evaluating _answersQueries per packet pegged the CPU and hung the
    // app.
    if (p.packetType == RnsPacketType.linkRequest &&
        (RnsCrypto.constantTimeEquals(p.destHash, relayDestHash) ||
            RnsCrypto.constantTimeEquals(p.destHash, rpcDestHash)) &&
        _answersQueries) {
      // Accept relay links on the dedicated relay dest AND on the configured RPC
      // dest (the chat dest in Aurora). The dests are disjoint when overridden,
      // and a peer that only has a path to our chat dest dials that one.
      await _accept(p);
      return true;
    }
    if (p.destType == RnsDestType.link) {
      final id = _hex(p.destHash);
      final i = _in[id];
      if (i != null) {
        if (i.link.status != RnsLinkStatus.active &&
            p.context == RnsContext.lrrtt) {
          i.link.handleRtt(p);
        } else {
          i.handleData(p);
        }
        return true;
      }
      final o = _out[id];
      if (o != null) {
        await _onOut(o, p);
        return true;
      }
    }
    return false;
  }

  // ── Client API ──────────────────────────────────────────────────────────

  /// Publish [e] to the relay owned by [relay]. Returns true if it was stored.
  Future<bool> publish(RnsIdentity relay, NostrEvent e,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final r = await _request(relay, RelayProtocol.event(e), timeout: timeout);
    return r != null && r.op == RelayOp.stored && r.ok;
  }

  /// Run a NIP-01 filter (set [NostrFilter.search] for NIP-50) against [relay].
  ///
  /// Tries the connectionless probe first when the host offers one and the peer
  /// advertises [RelayCap.probe]. A probe costs neither side a handshake, and a
  /// peer holding nothing answers with SILENCE — so the common empty query
  /// completes without a single Curve25519 operation anywhere.
  ///
  /// Falls back to a link when the peer is an older node, when the probe says
  /// the result is too big for a datagram, or when the query itself does not fit.
  Future<List<NostrEvent>> query(RnsIdentity relay, NostrFilter filter,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final sub = 's${_subSeq++}';
    final reqBytes = RelayProtocol.req(sub, filter);

    final p = probeQuery;
    if (p != null && reqBytes.length <= kNpdMaxPlaintext) {
      final r = await p(relay, reqBytes);
      if (r.supported) {
        final body = r.body;
        if (body == null) {
          // Silence. The peer holds nothing — and told us so for free.
          //
          // Honest caveat: a dropped packet is indistinguishable from "nothing".
          // We accept that here because these queries are re-run on the feed's
          // refresh cycle, so a lost probe costs freshness, not correctness — and
          // never a wrong answer.
          return const [];
        }
        final f = RelayProtocol.decode(body);
        if (f != null && f.op == RelayOp.result) {
          return f.events ?? const [];
        }
        // HAVE: the peer has data but it will not fit a datagram. NOW a link is
        // worth its cost — there is something real to move.
        log?.call('relay: probe says HAVE — opening a link for the payload');
      }
    }

    final r = await _request(relay, reqBytes, timeout: timeout);
    return r?.events ?? const [];
  }

  /// Pull one batch of pointer changes from another indexer.
  ///
  /// Returns the peer's answer, or null if it had nothing to say. A RESET is
  /// reported as [SyncOutcome.wasReset] with the peer's epoch: the caller drops
  /// its cursor and starts again, rather than silently missing everything that
  /// happened while its position was stale.
  ///
  /// Every record inside is verified against the PROVIDER that signed it before
  /// it can enter our map (see PointerSyncClient), so we never have to trust the
  /// indexer we are talking to — only the maths.
  Future<SyncOutcome?> syncPointers(
    RnsIdentity peer,
    PointerSyncClient client, {
    SyncCursor cursor = SyncCursor.none,
    int max = 64,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    final r = await _request(
      peer,
      RelayProtocol.syncReq(
          epoch: cursor.epoch, sinceSeq: cursor.seq, max: max),
      timeout: timeout,
    );
    if (r == null) return null;
    if (r.op == RelayOp.syncReset) {
      final epoch = r.epoch ?? '';
      log?.call('sync: reset by peer (epoch $epoch) — starting over');
      return SyncOutcome(
        cursor: SyncCursor(epoch, 0),
        wasReset: true,
      );
    }
    if (r.op != RelayOp.syncRes) return null;
    return client.merge(
      r.epoch ?? '',
      r.entries ?? const [],
      r.nextSeq,
      r.more,
    );
  }

  /// Count matches for [filter] on [relay].
  Future<int> countMatches(RnsIdentity relay, NostrFilter filter,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final sub = 's${_subSeq++}';
    final r = await _request(relay, RelayProtocol.count(sub, filter),
        timeout: timeout);
    return r?.count ?? 0;
  }

  /// Store-and-forward: deposit a packed LXMF message at propagation node
  /// [propNode] for offline recipient [recipientDeliveryDestHex]. Returns true
  /// if the node accepted it into its mailbox.
  Future<bool> deposit(
      RnsIdentity propNode, String recipientDeliveryDestHex, Uint8List packed,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final r = await _request(
        propNode, RelayProtocol.deposit(recipientDeliveryDestHex, packed),
        timeout: timeout);
    return r != null && r.op == RelayOp.stored && r.ok;
  }

  /// Recipient-authorized delete: ask [relay] to drop [ids]. [reqPubHex] is our
  /// NOSTR pubkey and [sigHex] a BIP-340 signature by it over
  /// sha256(ids.join(',')). The relay drops only ids whose event has a `p` tag
  /// == reqPubHex (i.e. addressed to us). Returns the number it dropped.
  Future<int> dropForRecipient(
      RnsIdentity relay, List<String> ids, String reqPubHex, String sigHex,
      {Duration timeout = const Duration(seconds: 20)}) async {
    if (ids.isEmpty) return 0;
    final r = await _request(relay, RelayProtocol.drop(reqPubHex, ids, sigHex),
        timeout: timeout);
    return (r != null && r.op == RelayOp.dropRes) ? r.count : 0;
  }

  /// Indexer side: deliver any mail queued for [recipient] (now believed online)
  /// via [router]. Removes each message once delivered. Returns delivered count.
  Future<int> flushFor(RnsIdentity recipient, LxmfRouter router) async {
    final destHex =
        _hex(RnsDestination.hash(recipient, kLxmfApp, kLxmfDeliveryAspects));
    var delivered = 0;
    for (final item in store.sfPending(destHex)) {
      final msg = LxmfMessage.unpack(item.blob);
      if (msg == null) {
        store.sfDelete(item.msgId); // undecodable — drop
        continue;
      }
      if (await router.send_(msg)) {
        store.sfDelete(item.msgId);
        delivered++;
      }
    }
    return delivered;
  }

  /// Does the mailbox hold anything for this recipient's delivery dest?
  bool hasMailFor(RnsIdentity recipient) {
    final destHex =
        _hex(RnsDestination.hash(recipient, kLxmfApp, kLxmfDeliveryAspects));
    return store.sfCount(destHex) > 0;
  }

  /// Next hop to [relay]'s relay destination, pulling a path first if we have
  /// none (we may know the peer's identity without a cached route). Mirrors
  /// FileTransferNode._ensurePath / LxmfRouter.
  Future<Uint8List?> _ensurePath(RnsIdentity relay) =>
      RnsLink.ensurePath(relay, rpcApp, rpcAspects,
          nextHopFor: nextHopFor,
          nextHopForDest: nextHopForDest,
          hasPathForDest: hasPathForDest,
          requestPath: requestPath);

  Future<RelayFrame?> _request(RnsIdentity relay, Uint8List reqBytes,
      {required Duration timeout}) async {
    final link = await RnsLink.initiator(relay, rpcApp, rpcAspects);
    link.nextHop = await _ensurePath(relay);
    final reqPkt = link.buildRequest();
    final done = Completer<RelayFrame?>();
    final tag = rpcTag;
    final rl = _RelayLink(link, send, (msg) {
      // On a shared dest the host tags our responses; strip the tag (and drop
      // frames tagged for another tenant) before decoding.
      final body = tag == null ? msg : _untagRpc(msg, tag);
      if (body != null && !done.isCompleted) {
        done.complete(RelayProtocol.decode(body));
      }
    });
    final outBytes = tag == null ? reqBytes : _tagRpc(reqBytes, tag);
    final pending = _Pending(link, rl, outBytes, done);
    final id = _hex(link.linkId!);
    _out[id] = pending;
    send(reqPkt.pack());
    final r = await done.future.timeout(timeout, onTimeout: () => null);
    _out.remove(id);
    return r;
  }

  static Uint8List _tagRpc(Uint8List body, int tag) =>
      Uint8List.fromList([tag, ...body]);
  static Uint8List? _untagRpc(Uint8List frame, int tag) =>
      (frame.isNotEmpty && frame[0] == tag)
          ? Uint8List.sublistView(frame, 1)
          : null;

  Future<void> _onOut(_Pending e, RnsPacket p) async {
    if (e.link.status != RnsLinkStatus.active) {
      if (p.packetType == RnsPacketType.proof &&
          p.context == RnsContext.lrproof) {
        final rtt = await e.link.handleProof(p);
        if (rtt == null) {
          if (!e.done.isCompleted) e.done.complete(null);
          return;
        }
        send(rtt.pack());
        e.rl.sendMessage(e.requestBytes); // link is active now
      }
      return;
    }
    e.rl.handleData(p);
  }

  // ── Connectionless probe (NPD) ────────────────────────────────────────────

  /// Answer a connectionless probe carrying a REQ, WITHOUT a link.
  ///
  /// Returns null when we hold nothing — the caller then sends no packet at all,
  /// which is the entire point: that case was 98 of 98 inbound queries and each
  /// one was buying a full Curve25519 handshake to say "I have nothing".
  ///
  /// Query semantics are identical to the link path ([_serve], RelayOp.req),
  /// self-scoping included, so a probe and a link answer the same question the
  /// same way.
  Future<({int type, Uint8List body})?> answerProbe(Uint8List body) async {
    final f = RelayProtocol.decode(body);
    if (f == null || f.op != RelayOp.req || f.filter == null) return null;
    if (!_answersQueries) return null;

    var filter = f.filter!;
    if (!serve) {
      final self = selfPubHex?.call();
      if (self == null) return null; // nothing of ours to offer -> silence
      filter = NostrFilter(
        authors: [self.toLowerCase()],
        kinds: filter.kinds,
        tags: filter.tags,
        since: filter.since,
        until: filter.until,
        limit: filter.limit,
      );
    }

    final events = store.query(filter);
    if (events.isEmpty) return null; // <- silence. no reply, no crypto.

    // We have something. Send it inline if it fits one datagram; otherwise just
    // say HOW MANY and let the peer open a link for the bulk (the link is worth
    // paying for when there is actually data to move).
    probesAnswered++;
    final full = RelayProtocol.result(f.subId ?? '', events, true);
    if (full.length <= kNpdMaxPlaintext) {
      log?.call('relay: probe answered inline -> ${events.length} event(s)');
      return (type: NpdType.result, body: full);
    }
    log?.call('relay: probe -> HAVE ${events.length} (open a link)');
    return (
      type: NpdType.have,
      body: RelayProtocol.countResult(f.subId ?? '', events.length),
    );
  }

  // ── Responder side ────────────────────────────────────────────────────────

  Future<void> _accept(RnsPacket request) async {
    // Dedup BEFORE the crypto. The link-id is a cheap truncated hash of the
    // request, while RnsLink.responder costs two Curve25519 scalar mults and
    // buildProof costs an Ed25519 signature. The SAME LINKREQUEST reaches us
    // once per interface it arrives on (and this runs ahead of the transport's
    // packet dedup), so without this check one peer's single request bought N
    // full handshakes. Re-send the CACHED proof bytes instead — re-calling
    // buildProof would sign again, which is the very cost we are avoiding.
    final id = _hex(RnsLink.linkIdFromRequest(request));
    final known = _in[id];
    if (known != null) {
      final proof = known.proof;
      if (proof != null) send(proof);
      return;
    }
    try {
      final link = await RnsLink.responder(identity, request);
      final rl = _RelayLink(link, send, (msg) => _serve(link, msg));
      _in[id] = rl;
      final proof = (await link.buildProof()).pack();
      rl.proof = proof;
      send(proof);
    } catch (err) {
      log?.call('relay: accept link failed: $err');
    }
  }

  void _serve(RnsLink link, Uint8List msg) {
    final f = RelayProtocol.decode(msg);
    final rl = _in[_hex(link.linkId!)];
    if (f == null || rl == null) return;
    final resp = _answerFrame(f);
    if (resp != null) rl.sendMessage(resp);
  }

  /// Answer a relay frame that arrived on a SHARED destination — the host that
  /// owns the link (e.g. the DHT/files node on the chat dest) demuxed it to us by
  /// its type tag. Stateless: returns the response bytes to send back (already
  /// UNtagged; the caller re-tags), or null for no reply. Same semantics as the
  /// link path ([_serve], [_answerFrame]).
  Future<Uint8List?> answerRelayFrame(Uint8List body) async {
    final f = RelayProtocol.decode(body);
    if (f == null) return null;
    return _answerFrame(f);
  }

  /// Compute the single response frame for a decoded relay request, running any
  /// side effects (store, sync). Returns null for no reply. Shared by the
  /// link-owned path ([_serve]) and the shared-dest demux ([answerRelayFrame]).
  Uint8List? _answerFrame(RelayFrame f) {
    try {
      switch (f.op) {
        case RelayOp.event:
          // A leaf (serve=false) accepts query links so it can share its own
          // posts, but it does NOT store other people's events pushed at it.
          if (!serve) return RelayProtocol.stored(false, 'not a host');
          final ev = f.event;
          if (ev == null) return RelayProtocol.stored(false, 'no event');
          final verdict = spam?.check(ev);
          if (verdict != null && !verdict.accepted) {
            return RelayProtocol.stored(false, verdict.reason);
          }
          // Hosting tier + quota: classify the author, then run the admission
          // gate. self (0) is always admitted; strangers can be refused past
          // their monthly note / storage caps.
          final tier = tierOfPub?.call(ev.pubkey) ?? 2;
          final reject = admitEvent?.call(ev, tier);
          if (reject != null) return RelayProtocol.stored(false, reject);
          final ok = store.put(ev, tier: tier);
          if (ok) onEvent?.call(ev);
          return RelayProtocol.stored(ok, ok ? null : 'rejected');
        case RelayOp.req:
          // Full hosts answer the whole query; a leaf scopes it to its OWN
          // posts (cheap + safe) so a joiner can still pull what this device
          // published, decentralised, without anyone hosting the network.
          var filter = f.filter!;
          if (!serve) {
            final self = selfPubHex?.call();
            if (self == null) {
              return RelayProtocol.result(f.subId ?? '', const [], true);
            }
            // Scope to our own posts: keep the querier's kinds/tags/since/limit
            // but force authors to just us.
            filter = NostrFilter(
              authors: [self.toLowerCase()],
              kinds: filter.kinds,
              tags: filter.tags,
              since: filter.since,
              until: filter.until,
              limit: filter.limit,
            );
          }
          final events = store.query(filter);
          reqsServed++;
          log?.call('relay: answered REQ -> ${events.length} event(s)'
              '${serve ? '' : ' (self-scoped)'}');
          return RelayProtocol.result(f.subId ?? '', events, true);
        case RelayOp.count:
          reqsServed++;
          return RelayProtocol.countResult(f.subId ?? '', store.count(f.filter));
        case RelayOp.deposit:
          final dest = f.dest;
          final blob = f.blob;
          var ok = false;
          if (dest != null && blob != null && blob.isNotEmpty) {
            final msgId = _hex(crypto.sha256.convert(blob).bytes);
            store.sfDeposit(msgId: msgId, dest: dest, blob: blob);
            // false also means "already queued" — treat as accepted.
            ok = true;
          }
          return RelayProtocol.stored(ok, ok ? null : 'rejected');
        case RelayOp.syncReq:
          // "What changed since (epoch, seq)?" — addresses, never content.
          final ps = pointerServer;
          if (ps == null) return RelayProtocol.syncReset('', 0);
          final answer = ps.answer(
            f.epoch ?? '',
            f.sinceSeq,
            max: f.count <= 0 ? 64 : (f.count > 256 ? 256 : f.count),
          );
          if (answer == null) {
            // Their cursor is not from this log, or is older than what we still
            // hold. Say so — a partial answer would leave a hole in their map.
            return RelayProtocol.syncReset(ps.log.epoch, ps.log.oldestSeq);
          }
          return RelayProtocol.syncRes(
            epoch: ps.log.epoch,
            entries: answer.entries,
            nextSeq: answer.nextSeq,
            more: answer.more,
          );
        case RelayOp.drop:
          // Recipient-authorized delete: verify the requester owns reqPub (a
          // BIP-340 sig over sha256 of the comma-joined ids), then drop only the
          // ids whose event is p-tagged to reqPub. Never deletes a third party's
          // events, and an unauthenticated request drops nothing.
          final reqPub = f.reqPub;
          final ids = f.ids;
          final sig = f.sig;
          var dropped = 0;
          if (serve && reqPub != null && ids != null && sig != null &&
              ids.isNotEmpty) {
            final digest =
                crypto.sha256.convert(utf8.encode(ids.join(','))).bytes;
            final msgHex = _hex(Uint8List.fromList(digest));
            var okSig = false;
            try {
              okSig = NostrCrypto.schnorrVerify(msgHex, sig, reqPub);
            } catch (_) {
              okSig = false;
            }
            if (okSig) dropped = store.dropForRecipient(ids, reqPub);
          }
          return RelayProtocol.dropResult(dropped);
        default:
          return null;
      }
    } catch (err) {
      log?.call('relay: serve error: $err');
      return null;
    }
  }

  /// Drop idle responder links (call periodically from the owner).
  void pruneLinks() => _in.clear();

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}

class _Pending {
  final RnsLink link;
  final _RelayLink rl;
  final Uint8List requestBytes;
  final Completer<RelayFrame?> done;
  _Pending(this.link, this.rl, this.requestBytes, this.done);
}

/// One full-duplex message channel over an established link. Sends one message
/// at a time (packet or Resource) and assembles one inbound message at a time;
/// in a request/response exchange the two never overlap, so inbound packets are
/// demuxed purely by context.
class _RelayLink {
  final RnsLink link;
  final void Function(Uint8List raw) send;
  final void Function(Uint8List msg) onMessage;

  RnsResourceSender? _tx; // our outbound Resource (if the message is large)
  RnsResourceReceiver? _rx; // inbound Resource being assembled

  /// The packed LRPROOF we already sent. Cached so a duplicate LINKREQUEST
  /// (same request arriving on another interface) is answered without signing
  /// it again.
  Uint8List? proof;

  _RelayLink(this.link, this.send, this.onMessage);

  /// Send [msg] over the link — single packet if it fits, else a Resource.
  void sendMessage(Uint8List msg) {
    if (msg.length <= _pktMax) {
      send(link.encrypt(msg, context: RnsContext.none).pack());
      return;
    }
    final s = RnsResourceSender(link, msg)..prepare();
    _tx = s;
    send(s.advertisementPacket().pack());
  }

  void handleData(RnsPacket p) {
    switch (p.context) {
      case RnsContext.resourceReq: // peer requests parts of our outbound Resource
        final tx = _tx;
        if (tx != null) {
          for (final part in tx.handleRequest(link.decrypt(p))) {
            send(part.pack());
          }
        }
        break;
      case RnsContext.resourcePrf: // peer proved receipt of a segment
        final tx = _tx;
        // RNS resource proofs are UNENCRYPTED — validate raw p.data.
        if (tx != null && tx.validateProof(p.data)) {
          if (!tx.complete) {
            send(tx.advertisementPacket().pack()); // next segment
          } else {
            _tx = null;
          }
        }
        break;
      case RnsContext.none: // a complete single-packet message
        onMessage(link.decrypt(p));
        break;
      case RnsContext.resourceAdv: // start/continue receiving an inbound Resource
      case RnsContext.resourceHmu:
      case RnsContext.resource:
        final rx = _rx ??= RnsResourceReceiver(link);
        for (final pkt in rx.handle(p)) {
          send(pkt.pack());
        }
        if (rx.complete) {
          _rx = null;
          onMessage(rx.payload!);
        } else if (rx.error != null) {
          _rx = null;
        }
        break;
      default:
        break;
    }
  }
}
