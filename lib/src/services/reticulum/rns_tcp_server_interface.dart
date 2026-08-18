/*
 * RNS TCP server interface — accepts inbound TCP connections (e.g. from phones)
 * and presents each as an [RnsInterface] to the transport. Combined with the
 * transport's announce rebroadcasting, this turns the host into a TRANSPORT hub:
 * an announce arriving from one client is relayed to all the others, so several
 * devices connected to one server can all talk to each other.
 *
 * Wire-compatible with RNS TCPServerInterface: HDLC-framed RNS packets, one
 * spawned connection per client.
 */
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'rns_hdlc.dart';
import 'rns_packet.dart' show kRnsLinkMtuMax;
import 'rns_transport.dart';

/// One accepted client connection, exposed as an interface to the transport.
class _RnsTcpServerConn implements RnsInterface {
  @override
  bool get announceOnly => false;
  // Path preference (from the owning server: 2 = internet TCP, 4 = WiFi Direct).
  @override
  final int speedRank;
  @override
  bool get edge => false;
  // TCP/HDLC carries arbitrary-size frames (link MTU discovery).
  @override
  int get hardwareMtu => kRnsLinkMtuMax;
  @override
  final String label;
  final Socket socket;
  final RnsHdlcDeframer _deframer = RnsHdlcDeframer();

  _RnsTcpServerConn(this.label, this.socket, {this.speedRank = 2});

  @override
  void send(Uint8List packetRaw) {
    try {
      socket.add(hdlcFrame(packetRaw));
    } catch (_) {}
  }
}

class RnsTcpServerInterface {
  final int port;
  final String bindHost;
  final RnsInterfaceRegistry transport;
  final void Function(Uint8List packetRaw, String via) onPacket;
  final void Function(String msg)? log;

  /// Fired when a new client connects. The WiFi-Direct GO uses this to
  /// re-announce its destinations over the fresh link so the just-joined client
  /// learns a rank-4 path (RNS routes per-destination — an announce sent before
  /// the client joined never reached it).
  final void Function()? onConnect;

  /// When false, the port is bound exclusively so a second listener fails
  /// (surfacing conflicts) instead of silently co-binding via SO_REUSEPORT.
  final bool shared;

  /// Dual-protocol port (docs/XPRS.md section 24.4): when set, a connection
  /// whose FIRST byte is not the HDLC flag `0x7E` is not Reticulum and is
  /// handed to this callback instead of the transport. The callback returns
  /// the sink that receives every subsequent chunk (the first chunk included);
  /// the socket stays owned here (closed on error/EOF), the callback owns
  /// what is written back. A client that connects and says nothing is assumed
  /// to be a listening Reticulum peer after a short wait.
  final void Function(Uint8List data) Function(Socket socket, String label)?
      onPlainText;

  /// Path preference + label prefix stamped on every accepted connection
  /// (defaults = internet TCP hub; a WiFi-Direct server passes 4 + 'wfd').
  final int connSpeedRank;
  final String labelPrefix;

  ServerSocket? _server;
  final List<_RnsTcpServerConn> _conns = [];
  int _seq = 0;

  RnsTcpServerInterface({
    required this.port,
    required this.transport,
    required this.onPacket,
    this.bindHost = '0.0.0.0',
    this.log,
    this.shared = true,
    this.connSpeedRank = 2,
    this.labelPrefix = 'tcps',
    this.onConnect,
    this.onPlainText,
  });

  int get connectionCount => _conns.length;

  /// The port actually bound — differs from [port] when 0 asked the OS to
  /// pick one (tests do).
  int? get boundPort => _server?.port;

  Future<void> bind() async {
    final s = await ServerSocket.bind(bindHost, port, shared: shared);
    _server = s;
    log?.call('TCP server listening on $bindHost:$port');
    s.listen(_onClient, onError: (e) => log?.call('server error: $e'));
  }

  void _onClient(Socket socket) {
    socket.setOption(SocketOption.tcpNoDelay, true);
    final label =
        '$labelPrefix#${_seq++}:${socket.remoteAddress.address}:${socket.remotePort}';

    // One protocol per connection, decided by the first byte (docs/XPRS.md
    // section 24.4): the HDLC flag 0x7E is Reticulum, printable text is XPRS.
    // The socket has a single-subscription stream, so ONE listener routes by
    // whichever of these two is set once the first chunk arrives.
    _RnsTcpServerConn? conn;
    void Function(Uint8List data)? textSink;
    Timer? undecided;

    void attachRns() {
      final c = _RnsTcpServerConn(label, socket, speedRank: connSpeedRank);
      conn = c;
      _conns.add(c);
      transport.addInterface(c);
      log?.call('client connected $label (${_conns.length} total)');
      try {
        onConnect?.call();
      } catch (_) {}
    }

    if (onPlainText == null) {
      attachRns();
    } else {
      // A Reticulum peer that connects and only listens never sends a first
      // byte to judge — after a short silence, treat it as the RNS client it
      // almost certainly is so it still receives announces.
      undecided = Timer(const Duration(seconds: 2), () {
        if (conn == null && textSink == null) attachRns();
      });
    }

    socket.listen(
      (data) {
        if (conn == null && textSink == null && data.isNotEmpty) {
          undecided?.cancel();
          if (data[0] == 0x7E) {
            attachRns();
          } else {
            log?.call('client $label speaks plain text');
            try {
              textSink = onPlainText!(socket, label);
            } catch (e) {
              log?.call('plain-text attach error: $e');
              socket.destroy();
              return;
            }
          }
        }
        final c = conn;
        if (c != null) {
          for (final frame in c._deframer.feed(data)) {
            try {
              onPacket(frame, label);
            } catch (e) {
              log?.call('onPacket error: $e');
            }
          }
        } else {
          try {
            textSink?.call(data);
          } catch (e) {
            log?.call('plain-text error: $e');
          }
        }
      },
      onError: (e) {
        undecided?.cancel();
        if (conn != null) {
          _drop(conn!);
        } else {
          socket.destroy();
        }
      },
      onDone: () {
        undecided?.cancel();
        if (conn != null) {
          _drop(conn!);
        } else {
          socket.destroy();
        }
      },
      cancelOnError: true,
    );
  }

  void _drop(_RnsTcpServerConn conn) {
    if (!_conns.remove(conn)) return;
    transport.removeInterface(conn);
    try {
      conn.socket.destroy();
    } catch (_) {}
    log?.call('client disconnected ${conn.label} (${_conns.length} left)');
  }

  Future<void> close() async {
    for (final c in List.of(_conns)) {
      _drop(c);
    }
    try {
      await _server?.close();
    } catch (_) {}
    _server = null;
  }
}
