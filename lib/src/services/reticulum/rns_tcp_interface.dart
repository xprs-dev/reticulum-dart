/*
 * RNS TCP client interface (wire-compatible, RNS 1.3.5 — TCPClientInterface).
 *
 * Connects to a TCPServerInterface (e.g. a Python rnsd), sends RNS packets as
 * HDLC frames, and deframes inbound bytes into packets. IFAC is disabled (the
 * default for a passphrase-less TCP interface), so packets go on the wire raw,
 * HDLC-framed.
 */
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'rns_hdlc.dart';
import 'rns_packet.dart' show kRnsLinkMtuMax;
import 'rns_transport.dart';

class RnsTcpInterface implements RnsInterface {
  @override
  bool get announceOnly => false;
  // Path preference. Default 2 (internet TCP); a WiFi-Direct link passes 4 so
  // the dedicated P2P pipe beats even a shared LAN (3).
  @override
  final int speedRank;
  @override
  bool get edge => false;

  // TCP/HDLC carries arbitrary-size frames, so advertise the link-MTU-discovery
  // ceiling (matches reference RNS TCPInterface.HW_MTU) for big resource parts.
  @override
  int get hardwareMtu => kRnsLinkMtuMax;

  final String host;
  final int port;
  @override
  final String label;
  final void Function(Uint8List packetRaw) onPacket;
  final void Function(String msg)? log;

  /// Fired once when the socket closes or errors, so the owner can tear the
  /// dead uplink down and reconnect (e.g. after the device's network changes).
  final void Function()? onDisconnect;

  Socket? _socket;
  final RnsHdlcDeframer _deframer = RnsHdlcDeframer();
  bool _connected = false;
  bool _notifiedDown = false;

  RnsTcpInterface({
    required this.host,
    required this.port,
    required this.onPacket,
    this.log,
    this.onDisconnect,
    this.speedRank = 2,
    String? label,
  }) : label = label ?? '$host:$port';

  bool get isConnected => _connected;

  Future<void> connect({Duration timeout = const Duration(seconds: 10)}) async {
    final s = await Socket.connect(host, port, timeout: timeout);
    s.setOption(SocketOption.tcpNoDelay, true);
    _enableKeepalive(s);
    _socket = s;
    _connected = true;
    log?.call('TCP connected to $host:$port');
    s.listen(
      (data) {
        for (final frame in _deframer.feed(data)) {
          try {
            onPacket(frame);
          } catch (e) {
            log?.call('onPacket error: $e');
          }
        }
      },
      onError: (e) {
        log?.call('TCP error: $e');
        _connected = false;
        _notifyDown();
      },
      onDone: () {
        log?.call('TCP closed');
        _connected = false;
        _notifyDown();
      },
      cancelOnError: true,
    );
  }

  /// Turn on TCP keepalive and (on Linux/Android) tune it aggressively so a
  /// half-open socket — the network changed under us and the peer's FIN/RST
  /// never arrived — is detected by the kernel in ~2 min instead of the ~2 h
  /// default. Without this a wedged uplink looks alive forever: no onDone/onError
  /// fires, the owner never reconnects, and announces silently stop flowing.
  /// Best-effort and non-fatal — unsupported platforms just keep SO_KEEPALIVE off.
  static void _enableKeepalive(Socket s) {
    // Linux/Android socket-option numbers (stable in the kernel ABI).
    const solSocket = 1, soKeepalive = 9; // SOL_SOCKET, SO_KEEPALIVE
    const ipprotoTcp = 6; // IPPROTO_TCP
    const tcpKeepidle = 4, tcpKeepintvl = 5, tcpKeepcnt = 6;
    void opt(int level, int option, int value) {
      try {
        s.setRawOption(RawSocketOption.fromInt(level, option, value));
      } catch (_) {/* option not supported on this platform — skip */}
    }

    opt(solSocket, soKeepalive, 1); // enable keepalive probes
    if (Platform.isLinux || Platform.isAndroid) {
      opt(ipprotoTcp, tcpKeepidle, 60); // idle 60s before first probe
      opt(ipprotoTcp, tcpKeepintvl, 15); // 15s between probes
      opt(ipprotoTcp, tcpKeepcnt, 4); // 4 failed probes → dead (~2 min total)
    }
  }

  void _notifyDown() {
    if (_notifiedDown) return;
    _notifiedDown = true;
    onDisconnect?.call();
  }

  /// Send one RNS packet (raw, already-packed bytes), HDLC-framed.
  void sendPacket(Uint8List packetRaw) {
    final s = _socket;
    if (s == null || !_connected) {
      throw StateError('TCP interface not connected');
    }
    s.add(hdlcFrame(packetRaw));
  }

  /// [RnsInterface] entry point — same as [sendPacket].
  @override
  void send(Uint8List packetRaw) => sendPacket(packetRaw);

  Future<void> close() async {
    _connected = false;
    try {
      await _socket?.flush();
      await _socket?.close();
    } catch (_) {}
    _socket?.destroy();
    _socket = null;
  }
}
