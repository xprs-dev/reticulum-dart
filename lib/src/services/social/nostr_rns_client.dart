/*
 * NostrRnsClient — the Reticulum transport: a NOSTR relay reachable over an RNS
 * link (RelayNode client). RNS relay access is request/response, so a live
 * subscription is emulated by an initial query plus periodic re-query for new
 * events (poll). This is what lets a relay live on the mesh instead of the
 * internet — same NOSTR semantics, different medium.
 *
 * The uri is `rns://<64-hex-identity-hash>`; the caller resolves that hash to an
 * [RnsIdentity] and hands it in, so this file stays free of address plumbing.
 */
import 'dart:async';

import '../../util/nostr_event.dart';
import '../reticulum/rns_identity.dart';
import 'nostr_relay_client.dart';
import 'nostr_relay_hub.dart' show kNostrPollInterval;
import 'relay_node.dart';
import 'relay_event_store.dart' show NostrFilter;

class NostrRnsClient implements NostrRelayClient {
  final RelayNode node;
  final RnsIdentity relay;
  @override
  final String uri;
  final Duration pollInterval;
  final void Function(String msg)? log;

  /// A Reticulum relay has no push channel, so a "subscription" is an initial
  /// query plus a re-query on this interval. [subscribe] runs the first query
  /// immediately, so this only governs how often we go BACK — which is a battery
  /// decision, not a freshness one (was 30s; the phone is in a pocket).
  NostrRnsClient(this.node, this.relay,
      {required this.uri,
      this.pollInterval = kNostrPollInterval,
      this.log});

  @override
  NostrEventCallback? onEvent;
  @override
  NostrEoseCallback? onEose;
  @override
  NostrClosedCallback? onClosed;
  @override
  NostrStatusCallback? onStatus;

  NostrRelayStatus _status = NostrRelayStatus.disconnected;
  final Map<String, List<NostrFilter>> _subs = {};
  final Map<String, int> _sinceOf = {}; // subId -> newest created_at seen
  Timer? _poll;
  bool _closed = false;

  @override
  NostrRelayStatus get status => _status;

  void _setStatus(NostrRelayStatus s) {
    if (_status == s) return;
    _status = s;
    onStatus?.call(s);
  }

  @override
  Future<void> connect() async {
    if (_closed) return;
    _poll ??= Timer.periodic(pollInterval, (_) => _pollAll());
    _setStatus(NostrRelayStatus.connecting);
  }

  @override
  void subscribe(String subId, List<NostrFilter> filters) {
    _subs[subId] = filters;
    connect();
    // ignore: discarded_futures
    _runSub(subId, initial: true);
  }

  Future<void> _pollAll() async {
    for (final id in _subs.keys.toList()) {
      await _runSub(id);
    }
  }

  Future<void> _runSub(String subId, {bool initial = false}) async {
    final filters = _subs[subId];
    if (filters == null || _closed) return;
    final since = _sinceOf[subId];
    var newest = since ?? 0;
    var any = false;
    for (final f in filters) {
      // On re-query only pull events newer than what we've already delivered.
      final ff = (since == null)
          ? f
          : NostrFilter(
              ids: f.ids,
              authors: f.authors,
              kinds: f.kinds,
              tags: f.tags,
              since: since + 1,
              until: f.until,
              limit: f.limit,
              search: f.search);
      try {
        final events = await node.query(relay, ff);
        any = true;
        for (final e in events) {
          if (e.verify()) {
            onEvent?.call(subId, e);
            if (e.createdAt > newest) newest = e.createdAt;
          }
        }
      } catch (e) {
        log?.call('$uri query failed: $e');
      }
    }
    _setStatus(any ? NostrRelayStatus.connected : NostrRelayStatus.error);
    _sinceOf[subId] = newest;
    if (initial) onEose?.call(subId);
  }

  @override
  int drainFrames() => 0;
  @override
  void resume() {}
  @override
  void disconnect() {}
  @override
  Future<void> reconnectFresh() async {}

  @override
  void reconnect() {} // no socket to cycle

  @override
  void unsubscribe(String subId) {
    _subs.remove(subId);
    _sinceOf.remove(subId);
  }

  @override
  Future<bool> publish(NostrEvent event) async {
    try {
      final ok = await node.publish(relay, event);
      _setStatus(ok ? NostrRelayStatus.connected : NostrRelayStatus.error);
      return ok;
    } catch (e) {
      log?.call('$uri publish failed: $e');
      _setStatus(NostrRelayStatus.error);
      return false;
    }
  }

  @override
  Future<void> close() async {
    _closed = true;
    _poll?.cancel();
    _poll = null;
    _setStatus(NostrRelayStatus.disconnected);
  }
}
