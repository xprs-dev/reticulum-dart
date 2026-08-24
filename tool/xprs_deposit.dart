// Bench tool, not CI: cp into test/ and run with flutter test on the bench.
// Bench-only: dial an XPRS node's RNS TCP server as a CLIENT and deposit one
// t:message for a third-party callsign over the wapp lane -- the internet
// sender of docs/XPRS.md 36.12. Not CI: it needs the node on the bench.
//   args: host, port, dest callsign
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:reticulum/reticulum.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('deposit one wire at the node', () async {
    const host = '127.0.0.1';
    const port = 4242;
    const target = 'X9TGT';
    final me = await RnsIdentity.generate();
    final now = DateTime.now().toUtc();
    String two(int n) => n.toString().padLeft(2, '0');
    final ts = '${now.year}-${two(now.month)}-${two(now.day)}_'
        '${two(now.hour)}:${two(now.minute)}:${two(now.second)}';
    final wire = 't:message f:X9NET d:$target ts:$ts '
        'm:APRSIS moment: hello from the internet';
    final app = BytesBuilder()
      ..addByte(4)
      ..add(utf8.encode('xprs'))
      ..add(utf8.encode(wire));
    final pkt = await RnsAnnounceBuilder.build(me, 'xprs', ['wapp'],
        appData: app.toBytes());
    final raw = pkt.pack();
    final iface = RnsTcpInterface(
      host: host,
      port: port,
      onPacket: (p) {},
      log: (m) => print('IF: $m'),
    );
    await iface.connect();
    iface.send(raw);
    print('DEPOSITED: $wire');
    await Future<void>.delayed(const Duration(seconds: 3));
  }, timeout: const Timeout(Duration(minutes: 2)));
}
