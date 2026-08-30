/*
 * NostrWsClient — the public internet transport: a NOSTR relay over WebSocket
 * (wss:// / ws://), NIP-01 JSON wire via [NostrWire].
 *
 * Uses package:web_socket_channel so the SAME code runs native (dart:io) and
 * web. Reconnects with capped backoff and replays live subscriptions on
 * reconnect, so a relay flap doesn't silently stop the feed.
 */
import 'dart:async';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../../util/nostr_event.dart';
import 'nostr_relay_client.dart';
import 'nostr_wire.dart';
import 'relay_event_store.dart' show NostrFilter;

class NostrWsClient implements NostrRelayClient {
  @override
  final String uri;
  final void Function(String msg)? log;

  NostrWsClient(this.uri, {this.log});

  @override
  NostrEventCallback? onEvent;
  @override
  NostrEoseCallback? onEose;
  @override
  NostrClosedCallback? onClosed;
  @override
  NostrStatusCallback? onStatus;

  WebSocketChannel? _ch;
  StreamSubscription<dynamic>? _sub;
  NostrRelayStatus _status = NostrRelayStatus.disconnected;
  bool _closed = false;
  Timer? _retry;
  int _backoffMs = 1000;

  // Live subscriptions, replayed on reconnect.
  final Map<String, List<NostrFilter>> _subs = {};
  // Publishes issued while offline, flushed on connect.
  final List<NostrEvent> _pendingPublish = [];

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
    // A pending backoff timer WINS over an on-demand connect. Callers reach
    // connect() through subscribe(), and a caller that subscribes on a short
    // period (the Social poll does, once a second) would otherwise cancel the
    // backoff every time and retry the same dead relay at its own cadence —
    // which off-grid means five failing DNS lookups a second, a device log that
    // holds twenty seconds of history, and a radio-idle phone that never sleeps.
    if (_retry?.isActive ?? false) return;
    if (_status == NostrRelayStatus.connected ||
        _status == NostrRelayStatus.connecting) {
      return;
    }
    _retry?.cancel();
    _setStatus(NostrRelayStatus.connecting);
    try {
      // Use the package's platform adapter. Direct IOWebSocketChannel handshakes
      // repeatedly timed out on Android while ordinary TCP remained healthy.
      final ch = WebSocketChannel.connect(Uri.parse(uri));
      _ch = ch;
      // ready throws on a failed handshake (bad TLS / unreachable host) — but on
      // Android it can also HANG forever, no error, no completion. An unbounded
      // await here is what froze the whole engine isolate: a poll waits for a
      // socket that will never open, every timer and message on that isolate
      // waits behind it, and the feed dies. Off-grid means bounding every wait.
      await ch.ready.timeout(const Duration(seconds: 8));
      // The handshake can complete AFTER close() ran — the poll opens a client,
      // fires connect() unawaited, and closes it a few seconds later while a slow
      // relay is still shaking hands. Without this guard, connect() would then
      // resurrect the socket: a live stream listener + idle timer on a client
      // everyone thinks is closed, leaked once per poll → the native heap climbs
      // to OOM. If we were closed/disconnected while connecting, let the socket go.
      if (_closed || _status != NostrRelayStatus.connecting) {
        try {
          ch.sink.close();
        } catch (_) {}
        if (identical(_ch, ch)) _ch = null;
        return;
      }
      _setStatus(NostrRelayStatus.connected);
      _backoffMs = 1000;
      _touch(); // start the idle watchdog for this socket
      _sub = ch.stream.listen(
        _onData,
        onError: (Object e) => _onDown('stream error: $e'),
        onDone: () => _onDown('closed'),
        cancelOnError: true,
      );
      // Replay subscriptions + flush queued publishes.
      for (final e in _subs.entries) {
        _send(NostrWire.req(e.key, e.value));
      }
      for (final e in List<NostrEvent>.from(_pendingPublish)) {
        _send(NostrWire.event(e));
      }
      _pendingPublish.clear();
    } catch (e) {
      // Drop the half-open channel a hung/failed handshake left behind, or it
      // leaks a socket per poll.
      try {
        _ch?.sink.close();
      } catch (_) {}
      _ch = null;
      _onDown('connect failed: $e');
    }
  }

  // A relay we hold open subscriptions on is never legitimately silent for
  // minutes: even a quiet one answers a REQ with EOSE. Silence with the socket
  // still "connected" is a half-open TCP — the phone changed network, or a
  // carrier NAT dropped the flow — and nothing else in the stack notices,
  // because there is no error to notice. Re-opening the SUBSCRIPTION (which the
  // firehose watchdog does) cannot help: the frames go into a dead socket.
  // The public subscriptions normally receive frames continuously. Silence past
  // this is treated as a dead flow so the feed does not remain frozen.
  static const int _idleMs = 45 * 1000;
  Timer? _idle;

  void _touch() {
    _idle?.cancel();
    _idle = Timer(const Duration(milliseconds: _idleMs), () {
      if (_closed || _status != NostrRelayStatus.connected) return;
      _onDown('idle ${_idleMs ~/ 1000}s — socket is dead, reconnecting');
    });
  }

  /// Frames received since the last report. "Connected" is a claim; this is
  /// evidence — a socket that is up and silent is the failure that cost hours.
  int framesIn = 0;
  @override
  int drainFrames() {
    final n = framesIn;
    framesIn = 0;
    return n;
  }

  void _onData(dynamic data) {
    framesIn++;
    _lastFrameMs = DateTime.now().millisecondsSinceEpoch;
    _touch();
    final raw = data is String ? data : data.toString();
    final msg = NostrWire.decode(raw);
    if (msg == null) return;
    switch (msg) {
      case NostrEventMsg(:final subId, :final event):
        // NO verify here. Verifying every delivery inline is what pegged the
        // engine isolate at 100% of a core (pure-Dart BigInt Schnorr, ~100ms a
        // signature on a budget phone): the kind-7 firehose alone is thousands
        // of events, four relays redeliver each one, and ~80% get rejected by
        // the content gate anyway. The HUB verifies exactly what it is about to
        // keep, deliver or persist — after dedup, after the gate — which cuts
        // the crypto by more than an order of magnitude and un-wedges every
        // timer and socket that shares this isolate.
        onEvent?.call(subId, event);
      case NostrEoseMsg(:final subId):
        onEose?.call(subId);
      case NostrNoticeMsg(:final message):
        log?.call('$uri notice: $message');
      case NostrClosedMsg(:final subId, :final message):
        // The relay REFUSED a subscription (rate-limited, too many filters,
        // auth-required…). Swallowing this is how a feed dies in silence: the
        // REQ is on the wire, no error is raised, and nothing ever arrives.
        log?.call('$uri CLOSED $subId: $message');
        onClosed?.call(subId, message);
      case NostrOkMsg():
      case NostrReqMsg():
      case NostrCloseMsg():
      case NostrPublishMsg():
        break; // client side ignores server-ingest frames
    }
  }

  void _onDown(String why) {
    if (_closed) return;
    _idle?.cancel();
    _idle = null;
    _setStatus(NostrRelayStatus.error);
    _sub?.cancel();
    _sub = null;
    // CLOSE THE SOCKET, not just the subscription. Cancelling the stream
    // listener does nothing to the TCP connection underneath: after the
    // relay's own close it sat in CLOSE_WAIT -- their FIN answered by
    // nothing -- and after the idle watchdog cycled it, it stayed fully
    // open with nobody reading. Every reconnect leaked one. Measured on
    // the Linux desktop after five hours: 1,323 sockets, 359 of them to one
    // relay, all through this line. The sink close is what sends our FIN.
    final ch = _ch;
    _ch = null;
    if (ch != null) {
      try {
        ch.sink.close();
      } catch (_) {}
    }
    log?.call('$uri down: $why');
    // Reconnect with capped exponential backoff; live subs are replayed above.
    _retry?.cancel();
    _retry = Timer(Duration(milliseconds: _backoffMs), () {
      _backoffMs = (_backoffMs * 2).clamp(1000, 60000);
      connect();
    });
  }

  void _send(String frame) {
    final ch = _ch;
    if (ch == null || _status != NostrRelayStatus.connected) return;
    try {
      ch.sink.add(frame);
    } catch (e) {
      _onDown('send failed: $e');
    }
  }

  @override
  void subscribe(String subId, List<NostrFilter> filters) {
    _subs[subId] = filters;
    log?.call('$uri: REQ $subId (${_subs.length} open)');
    if (_status == NostrRelayStatus.connected) {
      _send(NostrWire.req(subId, filters));
    } else {
      connect();
    }
  }

  /// The app came back to the foreground (or the user pulled to refresh).
  ///
  /// Android freezes a backgrounded app's sockets (Doze): they sit "connected"
  /// and deliver nothing, then error out all at once when the next keepalive
  /// ping hits the dead flow. Waiting for backoff timers to notice costs the
  /// user minutes of stale feed at exactly the moment they are looking at it.
  /// So: an errored socket reconnects NOW, and a "connected" one that has heard
  /// nothing for 30s is treated as the zombie it is and cycled.
  @override
  void resume() {
    if (_closed) return;
    if (_status == NostrRelayStatus.connected) {
      final idleMs = DateTime.now().millisecondsSinceEpoch - _lastFrameMs;
      if (_lastFrameMs > 0 && idleMs > 30 * 1000) {
        reconnect();
      }
      return;
    }
    // error / disconnected: skip the backoff — the user is watching.
    _retry?.cancel();
    _backoffMs = 1000;
    _setStatus(NostrRelayStatus.disconnected);
    connect();
  }

  int _lastFrameMs = 0;

  @override
  void disconnect() {
    // Close the socket, keep it reconnectable: _closed stays false and _subs
    // are kept so the next connect() replays them. The relay stops seeing a
    // long-lived client to cut.
    _idle?.cancel();
    _idle = null;
    _retry?.cancel();
    _sub?.cancel();
    _sub = null;
    try {
      _ch?.sink.close();
    } catch (_) {}
    _ch = null;
    _setStatus(NostrRelayStatus.disconnected);
  }

  @override
  Future<void> reconnectFresh() async {
    if (_closed) return;
    disconnect();
    await connect();
  }

  @override
  void reconnect() {
    if (_closed || _status != NostrRelayStatus.connected) return;
    try {
      _ch?.sink.close();
    } catch (_) {}
    _onDown('cycling the socket — the relay stopped answering');
  }

  @override
  void unsubscribe(String subId) {
    _subs.remove(subId);
    _send(NostrWire.close(subId));
  }

  @override
  Future<bool> publish(NostrEvent event) async {
    if (_status == NostrRelayStatus.connected) {
      _send(NostrWire.event(event));
    } else {
      _pendingPublish.add(event); // flushed on next connect
      connect();
    }
    return true;
  }

  @override
  Future<void> close() async {
    _closed = true;
    _idle?.cancel();
    _idle = null;
    _retry?.cancel();
    await _sub?.cancel();
    try {
      await _ch?.sink.close();
    } catch (_) {}
    _ch = null;
    _setStatus(NostrRelayStatus.disconnected);
  }
}
