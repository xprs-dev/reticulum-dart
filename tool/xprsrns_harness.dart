// Bench harness for the ESP32 `geogram_xprsrns` bearer: an RNS TCP server
// peer that accepts the board's uplink, prints every XPRS wire announced on
// the xprs.wapp lane, and answers the first sighting with one cmd:history.
//
// NOT an automated test -- it listens for 28 minutes. To run it on a bench:
//   cp tool/xprsrns_harness.dart test/xprsrns_bench_test.dart
//   flutter test test/xprsrns_bench_test.dart
// and point the board's config at this machine: cfg set rns_hub <ip>   (port defaults to 4242, Reticulum's own)
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:reticulum/reticulum.dart';
import 'package:flutter_test/flutter_test.dart';


class Reg implements RnsInterfaceRegistry {
  final ifaces = <RnsInterface>[];
  @override
  void addInterface(RnsInterface i) {
    ifaces.add(i);
    print('HARNESS: client connected (${i.label})');
  }

  @override
  void removeInterface(RnsInterface i) {
    ifaces.remove(i);
    print('HARNESS: client gone (${i.label})');
  }
}


void main() {
  test('xprsrns bench harness', () async {
    final args = <String>['4242', 'X3R8XX'];
  final port = int.parse(args.isNotEmpty ? args[0] : '4242');
  final askDest = args.length > 1 ? args[1] : '';
  final me = await RnsIdentity.generate();
  final wappName = RnsDestination.nameHash('xprs', ['wapp']);
  final reg = Reg();
  var asked = false;

  Future<void> onPacket(Uint8List raw, String via) async {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    final a = await validateAnnounce(p);
    if (a == null) {
      print('HARNESS: non-announce or invalid (${p.packetType})');
      return;
    }
    var same = a.nameHash.length == wappName.length;
    for (var i = 0; same && i < wappName.length; i++) {
      same = a.nameHash[i] == wappName[i];
    }
    if (!same) {
      print('HARNESS: announce for another app');
      return;
    }
    final d = a.appData;
    if (d.isEmpty) return;
    final tl = d[0];
    if (1 + tl > d.length) return;
    final tag = utf8.decode(d.sublist(1, 1 + tl), allowMalformed: true);
    final wire = utf8.decode(d.sublist(1 + tl), allowMalformed: true);
    print('WIRE [$tag] $wire');

    if (!asked && askDest.isNotEmpty && !wire.startsWith('t:result')) {
      asked = true;
      Timer(const Duration(seconds: 2), () async {
        final now = DateTime.now().toUtc();
        String two(int n) => n.toString().padLeft(2, '0');
        final ts = '${now.year}-${two(now.month)}-${two(now.day)}_'
            '${two(now.hour)}:${two(now.minute)}:${two(now.second)}';
        final since = now.subtract(const Duration(hours: 4));
        final sinceS = '${since.year}-${two(since.month)}-${two(since.day)}_'
            '${two(since.hour)}:${two(since.minute)}:${two(since.second)}';
        final ask = 't:command f:X9RNSQ d:$askDest ts:$ts scope:local '
            'cmd:history kind:message since:$sinceS';
        final app = BytesBuilder()
          ..addByte(4)
          ..add(utf8.encode('xprs'))
          ..add(utf8.encode(ask));
        final pkt = await RnsAnnounceBuilder.build(me, 'xprs', ['wapp'],
            appData: app.toBytes());
        final raw = pkt.pack();
        for (final i in reg.ifaces) {
          i.send(raw);
        }
        print('ASKED: $ask');
      });
    }
  }

  final srv = RnsTcpServerInterface(
    port: port,
    transport: reg,
    onPacket: (raw, via) => unawaited(onPacket(raw, via)),
    log: (m) => print('SRV: $m'),
  );
    await srv.bind();
    print('HARNESS: listening on $port');
    await Future<void>.delayed(const Duration(minutes: 28));
  }, timeout: const Timeout(Duration(minutes: 30)));
}
