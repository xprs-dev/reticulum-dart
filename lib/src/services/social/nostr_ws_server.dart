/*
 * NostrWsServer — makes THIS device a standard wss:// NOSTR relay.
 *
 * An HttpServer that upgrades WebSocket connections and speaks the NIP-01 JSON
 * wire against the local RelayEventStore, so any off-the-shelf NOSTR client on
 * the LAN (or reachable over the network) can use this device as a relay:
 *   - ["REQ", subId, filter…]  → stored events + ["EOSE", subId], sub kept open
 *   - ["EVENT", event]         → store.put + ["OK", id, accepted, msg]
 *   - ["CLOSE", subId]         → drop the sub
 * Freshly stored events (from this device OR ingested over other transports) are
 * LIVE-pushed to every open sub whose filter matches, via [broadcast] — wired by
 * the host through RelayEventStore.onPut, so every ingest path reaches open subs.
 *
 * Inbound EVENTs run the same acceptance policy as the RNS-side RelayNode when
 * the host supplies it: [spam] (size/PoW/rate), [tierOf] + [admitEvent]. The WS
 * door and the mesh door then enforce one policy.
 *
 * Email→npub conversion: a REQ for kind-30078 events whose `#d` value starts
 * with `mailto:` that finds nothing stored triggers [resolveMailto] (the host's
 * NIP-05 resolver). The resolver publishes a signed mapping event into the
 * store, which flows back out through onPut→broadcast to the still-open sub —
 * the requester receives the answer as a normal EVENT after EOSE (NIP-01).
 *
 * Bind pattern mirrors blossom_server.dart (HttpServer.bind on 0.0.0.0).
 */
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../../util/nostr_event.dart';
import 'nostr_wire.dart';
import 'relay_event_store.dart';
import 'spam.dart';

class _Conn {
  final WebSocket ws;
  final Map<String, List<NostrFilter>> subs = {};
  _Conn(this.ws);
}

class NostrWsServer {
  final RelayEventStore store;
  final int port;
  final void Function(String msg)? log;

  /// Open-network defences applied to WS-inbound EVENTs (size, PoW, rate).
  final SpamPolicy? spam;

  /// Hosting tier for an author (same closure shape RelayNode takes). Absent →
  /// default tier 2.
  final int Function(String pubkeyHex)? tierOf;

  /// Admission veto: return a rejection reason, or null to accept. Same closure
  /// shape RelayNode takes, so the host passes the identical policy to both.
  final String? Function(NostrEvent e, int tier)? admitEvent;

  /// Host's email→npub resolver (NIP-05). Fire-and-forget: the resolver stores
  /// a signed mapping event and onPut→broadcast delivers it to the open sub.
  final Future<void> Function(String email)? resolveMailto;

  /// NIP-11 relay information document supplier (name, pubkey, software, …).
  final Map<String, dynamic> Function()? relayInfo;

  /// Serve/push kind-4 encrypted DMs to WS clients. Off by default: payloads
  /// are encrypted but who↔whom↔when is metadata a public relay shouldn't leak.
  final bool serveEncryptedDms;

  NostrWsServer(
    this.store, {
    this.port = 4848,
    this.log,
    this.spam,
    this.tierOf,
    this.admitEvent,
    this.resolveMailto,
    this.relayInfo,
    this.serveEncryptedDms = false,
  });

  HttpServer? _http;
  final Set<_Conn> _conns = {};

  bool get running => _http != null;
  int get connections => _conns.length;

  /// Actual bound port (differs from [port] when constructed with port 0).
  int get boundPort => _http?.port ?? port;

  Future<bool> start() async {
    if (_http != null) return true;
    try {
      _http = await HttpServer.bind(InternetAddress.anyIPv4, port, shared: true);
      _http!.listen(_onRequest, onError: (Object e) => log?.call('ws srv: $e'));
      log?.call('NOSTR wss server on :$boundPort');
      return true;
    } catch (e) {
      log?.call('NOSTR wss server bind failed: $e');
      return false;
    }
  }

  Future<void> _onRequest(HttpRequest req) async {
    try {
      await _handle(req);
    } catch (e, st) {
      // Never let a request die silently: an escaped error leaves the socket
      // open and the client hanging until it times out.
      log?.call('request failed (${req.method} ${req.uri.path}): $e\n$st');
      try {
        req.response.statusCode = HttpStatus.internalServerError;
        await req.response.close();
      } catch (_) {}
    }
  }

  Future<void> _handle(HttpRequest req) async {
    log?.call('http ${req.method} ${req.uri.path} '
        'upgrade=${WebSocketTransformer.isUpgradeRequest(req)}');
    if (!WebSocketTransformer.isUpgradeRequest(req)) {
      // NIP-11 relay information document on a plain GET, so clients can probe.
      //
      // The body is written as explicit UTF-8 BYTES, not as a String. An
      // HttpResponse whose content type carries no charset encodes strings as
      // latin-1, so a single non-ASCII character (an em-dash in the relay
      // description was enough) throws inside this async handler — the
      // response is never closed and every probe hangs until it times out.
      const fallback = '{"name":"geogram","supported_nips":[1,9,11,50],'
          '"software":"geogram-aurora"}';
      var body = fallback;
      try {
        final info = relayInfo?.call();
        if (info != null) body = jsonEncode(info);
      } catch (e) {
        // A host that cannot describe itself still answers: anything thrown
        // here used to escape this async handler, leaving the connection open
        // forever so every probe timed out instead of failing fast.
        log?.call('nip-11 document failed, serving fallback: $e');
      }
      try {
        req.response
          ..statusCode = HttpStatus.ok
          ..headers.contentType =
              ContentType('application', 'nostr+json', charset: 'utf-8')
          ..add(utf8.encode(body));
      } catch (e) {
        log?.call('nip-11 write failed: $e');
      }
      try {
        await req.response.close();
      } catch (_) {}
      return;
    }
    try {
      final ws = await WebSocketTransformer.upgrade(req);
      final conn = _Conn(ws);
      _conns.add(conn);
      ws.listen(
        (data) => _onFrame(conn, data is String ? data : data.toString()),
        onDone: () => _conns.remove(conn),
        onError: (Object e) => _conns.remove(conn),
        cancelOnError: true,
      );
    } catch (e) {
      log?.call('ws upgrade failed: $e');
    }
  }

  void _onFrame(_Conn c, String raw) {
    final msg = NostrWire.decode(raw);
    if (msg == null) return;
    switch (msg) {
      case NostrReqMsg(:final subId, :final filters):
        c.subs[subId] = filters;
        for (final f in filters) {
          for (final e in store.query(f)) {
            if (!serveEncryptedDms &&
                e.kind == NostrEventKind.encryptedDirectMessage) {
              continue;
            }
            _send(c, NostrWire.eventFor(subId, e));
          }
        }
        _send(c, NostrWire.eose(subId));
        _maybeResolveMailto(filters);
      case NostrPublishMsg(:final event):
        final reason = _admit(event);
        final ok = reason == null;
        _send(c, NostrWire.ok(event.id ?? '', ok, reason ?? ''));
      // No explicit broadcast here: store.onPut fires it for every ingest
      // path, this one included.
      case NostrCloseMsg(:final subId):
        c.subs.remove(subId);
      default:
        break;
    }
  }

  /// Run the full acceptance chain on a WS-inbound event. Returns a NIP-20
  /// rejection reason, or null when the event was verified AND stored.
  String? _admit(NostrEvent event) {
    if (!event.verify()) return 'invalid: bad signature';
    final verdict = spam?.check(event);
    if (verdict != null && !verdict.accepted) {
      return 'blocked: ${verdict.reason ?? 'spam policy'}';
    }
    final tier = tierOf?.call(event.pubkey) ?? 2;
    final veto = admitEvent?.call(event, tier);
    if (veto != null) return 'blocked: $veto';
    if (!store.put(event, tier: tier)) return 'duplicate: already have it';
    return null;
  }

  /// Email→npub trigger: a REQ that asks for kind-30078 `#d` values starting
  /// `mailto:` and found nothing stored kicks the host resolver for each such
  /// address. The answer arrives on the open sub via onPut→broadcast.
  void _maybeResolveMailto(List<NostrFilter> filters) {
    final resolver = resolveMailto;
    if (resolver == null) return;
    for (final f in filters) {
      if (f.kinds != null &&
          !f.kinds!.contains(NostrEventKind.applicationSpecificData)) {
        continue;
      }
      final dValues = f.tags?['d'];
      if (dValues == null) continue;
      for (final d in dValues) {
        if (!d.startsWith('mailto:')) continue;
        final have = store.query(NostrFilter(
          kinds: const [NostrEventKind.applicationSpecificData],
          tags: {
            'd': [d]
          },
        ));
        if (have.isNotEmpty) continue; // already answered in the replay
        final email = d.substring('mailto:'.length);
        if (email.isEmpty) continue;
        log?.call('mailto resolve requested: $email');
        unawaited(resolver(email));
      }
    }
  }

  /// LIVE-push a stored event to every open sub whose filter matches. Wired to
  /// RelayEventStore.onPut by the host, so this relay's subscribers see events
  /// merged from ANY transport (mesh, internet, local publish, WS ingest).
  void broadcast(NostrEvent event) {
    if (!serveEncryptedDms &&
        event.kind == NostrEventKind.encryptedDirectMessage) {
      return;
    }
    for (final c in _conns) {
      for (final e in c.subs.entries) {
        if (e.value.any((f) => NostrWire.matches(f, event))) {
          _send(c, NostrWire.eventFor(e.key, event));
          break;
        }
      }
    }
  }

  void _send(_Conn c, String frame) {
    try {
      c.ws.add(frame);
    } catch (_) {
      _conns.remove(c);
    }
  }

  Future<void> stop() async {
    for (final c in _conns) {
      try {
        await c.ws.close();
      } catch (_) {}
    }
    _conns.clear();
    await _http?.close(force: true);
    _http = null;
  }
}
