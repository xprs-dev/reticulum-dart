// Shared BLE 5 connectionless-broadcast bus (Android). Bridges to the native
// Ble5 plugin (android/.../com/example/iwi/Ble5.kt), which owns ONE extended
// advertising set and multiplexes every registered frame onto it (round-robin
// with per-frame TTL). Every subsystem that wants connectionless broadcast —
// Reticulum announces (subtype 0x55) and APRS group chat (subtype 0x41) — shares
// this one bus, because phones generally can't run two extended advertising sets
// at once and two independent writers of one set would clobber each other.
//
// Send:    advertiseFrame(key, subtype, data, ttl)  — register/refresh a frame
//          removeFrame(key)                          — drop it early
// Receive: onFrame(subtype, handler)                 — demuxed inbound by subtype
//          startScan()                               — one shared extended scan
import 'dart:async';

import 'package:flutter/services.dart';

/// Manufacturer-data subtypes carried under company id 0xFFFF, marker 0x3E.
class Ble5Subtype {
  static const int rns = 0x55; // Reticulum packet
  // A Reticulum packet too big for one extended advert, split across several.
  // Its own subtype so a chunk is never mistaken for a whole packet (and never
  // lands in the APRS reassembler, which speaks a different framing).
  static const int rnsChunk = 0x56; // Reticulum packet fragment
  static const int aprs = 0x41; // APRS broadcast parcel ('A')
  static const int presence = 0x47; // GATT presence beacon ('G'): callsign
  static const int mesh = 0x4D; // street-mesh route beacon ('M'), doc/mesh.md
  static const int wfd = 0x57; // WiFi-Direct negotiation ('W'): ADVERT/REQ/OFFER
  // XPRS text packets ('X'), docs/XPRS.md — the discovery beacon and carried
  // mail. Its own subtype so a receiver never has to sniff a frame to tell XPRS
  // from the compact `FROM\x1FTO\x1Ftext` the chat wapp and the ESP32 still put
  // on 0x41, and so those two ignore what they cannot read instead of trying.
  static const int xprs = 0x58;
}

/// One inbound connectionless frame, already demuxed to a single subtype.
class Ble5Frame {
  final String addr; // advertiser address (rotating random MAC)
  final int rssi;
  final Uint8List data; // payload after marker+subtype
  const Ble5Frame(this.addr, this.rssi, this.data);
}

class Ble5Bus {
  Ble5Bus._();
  static final Ble5Bus instance = Ble5Bus._();

  /// Max payload that fits one extended advert here (leaves envelope headroom).
  /// APRS caps a message well under this (250 chars + metadata); longer content
  /// is split into multiline frames by the wapp.
  static const int maxFrame = 450;

  static const MethodChannel _method =
      MethodChannel('com.xprs.app/ble5');
  static const EventChannel _scan =
      EventChannel('com.xprs.app/ble5_scan');
  static const EventChannel _gattEvents =
      EventChannel('com.xprs.app/ble5_gatt');

  final Map<int, void Function(Ble5Frame)> _handlers = {};
  StreamSubscription? _sub;
  StreamSubscription? _gattSub;
  bool _scanning = false;
  bool? _supported;

  // ── Scan self-healing ────────────────────────────────────────────────────
  // Some devices (vendor power managers, BT adapter restarts) silently kill a
  // long-running BLE scan — or deny the first registration — while both sides
  // still believe they are scanning. Track the last delivered frame and force
  // a full native stop+start re-registration after an implausible silence.
  // Mesh beacons alone guarantee sub-30 s traffic whenever any peer is near,
  // and a restart on a genuinely lonely device is harmless (well under
  // Android's 5-starts/30 s throttle).
  int _lastFrameMs = 0;
  int _scanStartMs = 0;
  bool _wantScan = false;
  Timer? _scanWatchdog;
  static const int _silenceRestartMs = 150 * 1000;

  /// Optional log sink (the app wires this to its log service).
  void Function(String msg)? onLog;

  /// Force a full native re-registration of the scan.
  Future<void> restartScan() async {
    try {
      await _method.invokeMethod('stopScan');
    } catch (_) {}
    _scanning = false;
    await startScan();
  }

  void _armScanWatchdog() {
    _scanWatchdog ??= Timer.periodic(const Duration(seconds: 60), (_) {
      if (!_wantScan) return;
      final now = DateTime.now().millisecondsSinceEpoch;
      final lastSeen = _lastFrameMs > _scanStartMs ? _lastFrameMs : _scanStartMs;
      if (now - lastSeen > _silenceRestartMs) {
        onLog?.call(
            'BLE5: scan silent ${(now - lastSeen) ~/ 1000}s — re-registering');
        // ignore: discarded_futures
        restartScan();
      }
    });
  }

  // Native GATT callbacks. The whole GATT large-file path is native (server +
  // client + legacy connectable advert + legacy discovery scan) — one coordinated
  // stack, unlike the two Flutter plugins whose dual-role confused Android's GATT
  // handle cache.
  void Function()? onGattConnected; // our client link is up + ready
  void Function()? onGattDisconnected; // our client link dropped
  void Function(Uint8List data)? onGattData; // client received on FFF2 (receipts)
  void Function(String address, String callsign)? onGattDiscovered; // peer beacon
  void Function(String address, Uint8List data)? onGattServerData; // FFF1 write in
  void Function(String address)? onGattServerConnected;
  void Function(String address)? onGattServerDisconnected;

  /// The controller REFUSED to put our advert on air (status from
  /// AdvertisingSetCallback). Queuing a frame says nothing about whether it was
  /// aired, so without this a device stays mute while reporting that it beacons.
  void Function(int status)? onAdvertFailed;

  /// Whether the radio is switched on RIGHT NOW. Never cached — [supported]
  /// answers a permanent question about the controller, and using that as a
  /// liveness check means composing frames for a radio that is off.
  Future<bool> adapterOn() async {
    try {
      return (await _method.invokeMethod<bool>('adapterOn')) ?? false;
    } catch (_) {
      return false;
    }
  }

  /// Whether the device supports BLE 5 extended advertising.
  Future<bool> supported() async {
    final cached = _supported;
    if (cached != null) return cached;
    bool ok;
    try {
      ok = (await _method.invokeMethod<bool>('supported')) ?? false;
    } catch (_) {
      ok = false;
    }
    _supported = ok;
    if (ok) {
      // Learn THIS controller's true per-frame payload ceiling. Chips vary
      // wildly (255 B is common vs the 1650 B spec max); an oversized frame is
      // rejected by the stack, not truncated, so senders must route anything
      // bigger over GATT instead of assuming the optimistic [maxFrame].
      try {
        final n = await _method.invokeMethod<int>('maxPayload');
        // Take what the controller says, even when it is small. The old guard
        // (`n > 30`) DISCARDED a legacy-sized answer and kept the optimistic
        // 450 — on exactly the device least able to honour it. Every frame
        // between the real ceiling and 450 was then refused by the native
        // admission check, aired nowhere, while the app went on believing it
        // was broadcasting.
        if (n != null && n >= 20) {
          _maxPayload = n < maxFrame ? n : maxFrame;
          onLog?.call('BLE5: controller carries ${_maxPayload}B per advert');
        }
      } catch (_) {}
    }
    return ok;
  }

  int _maxPayload = maxFrame;

  /// Largest payload one extended advert can carry ON THIS DEVICE — the
  /// effective broadcast cap for the size router (≤ [maxFrame]). Valid after
  /// [supported] resolves true; conservative default before that.
  int get maxPayload => _maxPayload;

  /// Route inbound frames of [subtype] to [handler]. One handler per subtype.
  void onFrame(int subtype, void Function(Ble5Frame) handler) =>
      _handlers[subtype] = handler;

  /// Whether anyone has asked for the shared extended scan, and whether the
  /// native side confirmed it is up. Diagnostics only: the two disagreeing is
  /// exactly the state that made the radio silently deaf, so both are reported.
  bool get wantScan => _wantScan;
  bool get scanning => _scanning;

  /// Milliseconds since a frame last came off the scan, or null if never.
  int? get msSinceLastFrame => _lastFrameMs == 0
      ? null
      : DateTime.now().millisecondsSinceEpoch - _lastFrameMs;

  /// Begin the shared extended scan (idempotent). Demuxes by subtype.
  Future<void> startScan() async {
    _wantScan = true;
    _armScanWatchdog();
    if (_scanning) return;
    _sub ??= _scan.receiveBroadcastStream().listen((event) {
      if (event is! Map) return;
      _lastFrameMs = DateTime.now().millisecondsSinceEpoch;
      final subtype = (event['subtype'] as int?) ?? -1;
      final h = _handlers[subtype];
      if (h == null) return;
      final raw = event['data'];
      final data = raw is Uint8List
          ? raw
          : (raw is List<int> ? Uint8List.fromList(raw) : Uint8List(0));
      final addr = (event['addr'] as String?) ?? '';
      final rssi = (event['rssi'] as int?) ?? 0;
      h(Ble5Frame(addr, rssi, data));
    });
    try {
      final ok = await _method.invokeMethod<bool>('startScan');
      // `ok ?? true` used to latch _scanning on a null answer — the shape a
      // MissingPluginException-free notImplemented gives back — after which the
      // `if (_scanning) return` above made every retry a no-op forever. Only a
      // literal true means the scan is up.
      _scanning = ok == true;
      _scanStartMs = DateTime.now().millisecondsSinceEpoch;
      if (ok != true) {
        onLog?.call('BLE5: native startScan refused ($ok) — watchdog will retry');
      }
    } catch (e) {
      _scanning = false;
      onLog?.call('BLE5: startScan failed: $e');
    }
  }

  /// Register/refresh a keyed broadcast frame. Re-calling with the same [key]
  /// refreshes its TTL (and replaces the data). The native rotation airs it.
  /// Register/refresh a frame on the shared advertising set. Returns whether
  /// the native side ACCEPTED it — a frame over this controller's advert
  /// ceiling is refused outright, and a caller that assumes success then
  /// reports beacons it never sent.
  Future<bool> advertiseFrame(String key, int subtype, Uint8List data,
      {Duration ttl = const Duration(seconds: 35), bool prio = false}) async {
    try {
      final ok = await _method.invokeMethod<bool>('advertiseFrame', {
        'key': key,
        'subtype': subtype,
        'data': data,
        'ttlMs': ttl.inMilliseconds,
        // Traffic (a link handshake, a message) is aired ahead of presence.
        'prio': prio,
      });
      if (ok == false) _advertFailures++;
      return ok ?? false;
    } catch (e) {
      _advertFailures++;
      _advertLastError = '$e';
      return false;
    }
  }

  int _advertFailures = 0;
  String? _advertLastError;

  /// Adverts the controller refused since start, and the last reason.
  int get advertFailures => _advertFailures;
  String? get advertLastError => _advertLastError;

  /// What the RADIO reports it is doing — on-air state, attempts, refusals and
  /// how long since it last heard ANY advert (ours or anyone's). "Heard
  /// nothing" and "nobody is around" are indistinguishable without this, and
  /// they have completely different causes.
  Future<Map<String, dynamic>> radioStatus() async {
    try {
      final m = await _method.invokeMethod<Map<dynamic, dynamic>>('radioStatus');
      if (m == null) return const {};
      return m.map((k, v) => MapEntry(k.toString(), v));
    } catch (_) {
      return const {};
    }
  }

  Future<void> removeFrame(String key) async {
    try {
      await _method.invokeMethod('removeFrame', {'key': key});
    } catch (_) {}
  }

  /// Begin listening for native GATT-client events (connected/disconnected/data).
  void startGattEvents() {
    _gattSub ??= _gattEvents.receiveBroadcastStream().listen((event) {
      if (event is! Map) return;
      Uint8List? bytes(dynamic raw) => raw is Uint8List
          ? raw
          : (raw is List<int> ? Uint8List.fromList(raw) : null);
      final addr = (event['address'] as String?) ?? '';
      switch (event['event']) {
        case 'connected':
          onGattConnected?.call();
          break;
        case 'disconnected':
          onGattDisconnected?.call();
          break;
        case 'data':
          final d = bytes(event['data']);
          if (d != null) onGattData?.call(d);
          break;
        case 'discovered':
          onGattDiscovered?.call(addr, (event['callsign'] as String?) ?? '');
          break;
        case 'server_data':
          final d = bytes(event['data']);
          if (d != null) onGattServerData?.call(addr, d);
          break;
        case 'server_connected':
          onGattServerConnected?.call(addr);
          break;
        case 'server_disconnected':
          onGattServerDisconnected?.call(addr);
          break;
        case 'advertFailed':
          _advertFailures++;
          _advertLastError = 'startAdvertisingSet status=${event['status']}';
          onAdvertFailed?.call((event['status'] as int?) ?? -1);
          break;
      }
    });
  }

  /// Start the native GATT server + legacy connectable presence beacon + legacy
  /// discovery scan (the whole point-to-point transfer endpoint).
  Future<void> startServer(String callsign) async {
    try {
      await _method.invokeMethod('startServer', {'callsign': callsign});
    } catch (_) {}
  }

  Future<void> stopServer() async {
    try {
      await _method.invokeMethod('stopServer');
    } catch (_) {}
  }

  /// Notify the connected central on FFF2 (receipts / reverse data).
  Future<void> serverNotify(Uint8List data) async {
    try {
      await _method.invokeMethod('serverNotify', {'data': data});
    } catch (_) {}
  }

  /// Open a GATT link to a peer by BLE address (learned from the scan).
  Future<void> gattConnect(String address, {bool auto = false}) async {
    try {
      await _method.invokeMethod(
          'gattConnect', {'address': address, 'auto': auto});
    } catch (_) {}
  }

  /// Write bytes to the connected peer's FFF1 (no response).
  Future<void> gattWrite(Uint8List data) async {
    try {
      await _method.invokeMethod('gattWrite', {'data': data});
    } catch (_) {}
  }

  Future<void> gattDisconnect() async {
    try {
      await _method.invokeMethod('gattDisconnect');
    } catch (_) {}
  }

  Future<void> stopAdvertise() async {
    try {
      await _method.invokeMethod('stopAdvertise');
    } catch (_) {}
  }

  Future<void> stopScan() async {
    // Stopping is a DECISION, not a failure: the caller stops the scan to give
    // the radio to a GATT session. Leaving _wantScan set meant this object's own
    // silence watchdog re-registered the scan ~150 s later, on top of the very
    // transfer the scan was stopped for — the same mistake, one layer down.
    _wantScan = false;
    try {
      await _method.invokeMethod('stopScan');
    } catch (_) {}
    _scanning = false;
    // The EventChannel subscription STAYS. Cancelling it fires onCancel on the
    // native side, which nulls the sink every scan result is written to — so
    // adverts kept arriving, kept being counted, and were thrown away one line
    // later, with nothing anywhere saying so. That is what made the phone deaf
    // for a whole session after a single GATT link. The subscription is inert
    // while the native scan is stopped; keeping it costs nothing and means a
    // restart is heard immediately.
  }
}
