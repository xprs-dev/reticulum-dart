/*
 * Dual-protocol TCP port (aurora docs/XPRS.md section 24.4): one listener,
 * first byte decides. 0x7E = HDLC-framed Reticulum; printable text goes to
 * the plain-text sink; a silent client is assumed Reticulum after the wait.
 */
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:reticulum/reticulum.dart';
import 'package:flutter_test/flutter_test.dart';

class _Registry implements RnsInterfaceRegistry {
  final added = <RnsInterface>[];
  @override
  void addInterface(RnsInterface iface) => added.add(iface);
  @override
  void removeInterface(RnsInterface iface) => added.remove(iface);
}

void main() {
  test('first byte routes: HDLC to the transport, text to the sink',
      () async {
    final reg = _Registry();
    final packets = <Uint8List>[];
    final textLines = <String>[];
    final srv = RnsTcpServerInterface(
      port: 0,
      transport: reg,
      onPacket: (raw, via) => packets.add(raw),
      onPlainText: (socket, label) {
        return (Uint8List data) {
          textLines.add(utf8.decode(data));
          socket.add(utf8.encode('t:pong f:TEST\n'));
        };
      },
    );
    await srv.bind();
    final port = srv.boundPort!;

    // A Reticulum client: HDLC frame first.
    final rns = await Socket.connect('127.0.0.1', port);
    final payload = Uint8List.fromList([1, 2, 3, 4]);
    rns.add(hdlcFrame(payload));
    await rns.flush();
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(packets, hasLength(1));
    expect(packets.single, payload);
    expect(reg.added, hasLength(1), reason: 'registered as an RNS interface');

    // An XPRS client: a text line, and the sink's reply comes back.
    final xprs = await Socket.connect('127.0.0.1', port);
    final replies = <String>[];
    xprs.listen((d) => replies.add(utf8.decode(d)));
    xprs.add(utf8.encode('t:ping f:X1TEST\n'));
    await xprs.flush();
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(textLines.join(), contains('t:ping f:X1TEST'));
    expect(replies.join(), contains('t:pong f:TEST'));
    expect(reg.added, hasLength(1),
        reason: 'a text connection is never an RNS interface');

    rns.destroy();
    xprs.destroy();
    await srv.close();
  });

  test('a silent client becomes a Reticulum listener after the wait',
      () async {
    final reg = _Registry();
    final srv = RnsTcpServerInterface(
      port: 0,
      transport: reg,
      onPacket: (raw, via) {},
      onPlainText: (socket, label) => (data) {},
    );
    await srv.bind();
    final quiet = await Socket.connect('127.0.0.1', srv.boundPort!);
    await Future<void>.delayed(const Duration(milliseconds: 2500));
    expect(reg.added, hasLength(1),
        reason: 'listen-only RNS clients must still receive announces');
    quiet.destroy();
    await srv.close();
  });
}
