// Bench driver for XPRS.md 11.9 and 11.10: claim a station and set it up
// over the LAN lane (UDP 4242), exactly as a phone does over Bluetooth, and
// print every answer. It is how the station side is tested before, and
// independently of, the app.
//
//   dart run tool/xprs_setup_bench.dart --key ~/.xprs/bench-owner.nsec \
//       --to X30Y64 claim
//   ... wifi --ssid "Casa do Mar" --pass "sardinha na brasa 2026"
//   ... set nick=roof zone=+01:00 ap=on
//   ... zdiag | rekey | clearpass --pass xxxxxxxx | replay | listen
//
// The owner key is a file holding an nsec; one is made there if it is
// missing. The station's own key, which a sealed body is sealed to, is
// learned from its q:owner or t:identity, so the station has to be heard
// first: the tool listens up to two minutes for it.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';
import 'package:reticulum/src/util/nostr_key_generator.dart';
import 'package:reticulum/src/util/xprs_crypto.dart';

const port = 4242;

String arg(List<String> a, String n, [String? or]) {
  final i = a.indexOf('--$n');
  if (i >= 0 && i + 1 < a.length) return a[i + 1];
  if (or != null) return or;
  stderr.writeln('missing --$n');
  exit(2);
}

String stamp([int plus = 0]) {
  final t = DateTime.now().toUtc().add(Duration(seconds: plus));
  String p(int v, [int w = 2]) => v.toString().padLeft(w, '0');
  return '${p(t.year, 4)}-${p(t.month)}-${p(t.day)}_'
      '${p(t.hour)}:${p(t.minute)}:${p(t.second)}';
}

BigInt big(List<int> b) => b.fold(BigInt.zero, (a, x) => (a << 8) | BigInt.from(x));

List<int> unhex(String h) =>
    List.generate(h.length ~/ 2, (i) => int.parse(h.substring(2 * i, 2 * i + 2), radix: 16));

String b64u(List<int> b) => base64Url.encode(b).replaceAll('=', '');

// Section 5: the identifier is sha256 of the packet without sig: and via:.
String idOf(String wire) {
  final canon = wire
      .split(' ')
      .where((t) => !t.startsWith('sig:') && !t.startsWith('via:'))
      .join(' ');
  return sha256.convert(utf8.encode(canon)).toString().substring(0, 6);
}

String sign(String wire, BigInt d) {
  final digest = Uint8List.fromList(sha256.convert(utf8.encode(wire)).bytes);
  return '$wire sig:${XprsCrypto.b85encode(XprsCrypto.sign(digest, d))}';
}

String? field(String wire, String k) {
  for (final t in wire.split(' ')) {
    if (t.startsWith('$k:')) return t.substring(k.length + 1);
  }
  return null;
}

Future<void> main(List<String> argv) async {
  final keyFile = File(arg(argv, 'key'));
  if (!keyFile.existsSync()) {
    final k = NostrKeyGenerator.generateKeyPair();
    keyFile.createSync(recursive: true);
    keyFile.writeAsStringSync('${k.nsec}\n');
    stderr.writeln('made a bench owner key in ${keyFile.path}');
  }
  final nsec = keyFile.readAsStringSync().trim();
  final privHex = NostrCrypto.decodeNsec(nsec);
  final d = big(unhex(privHex));
  final npub = NostrCrypto.encodeNpub(NostrCrypto.derivePublicKey(privHex));
  final me = NostrKeyGenerator.deriveCallsign(npub);
  final to = arg(argv, 'to', '');
  final bcast = InternetAddress(arg(argv, 'bcast', '255.255.255.255'));
  final step = argv.lastWhere((a) => !a.startsWith('--') && !a.contains('='),
      orElse: () => 'listen');
  stdout.writeln('owner $me ($npub)');

  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port,
      reuseAddress: true, reusePort: true);
  sock.broadcastEnabled = true;
  final heard = StreamController<String>.broadcast();
  sock.listen((e) {
    if (e != RawSocketEvent.read) return;
    final g = sock.receive();
    if (g == null) return;
    final w = utf8.decode(g.data, allowMalformed: true);
    if (!w.startsWith('t:')) return;
    heard.add(w);
  });
  heard.stream.listen((w) {
    final f = field(w, 'f') ?? '';
    if (f == me) return;
    if (to.isNotEmpty && f != to && field(w, 'd') != me) return;
    if (w.startsWith('t:result') || w.contains('q:owner') ||
        w.startsWith('t:identity') || step == 'listen') {
      stdout.writeln('<- ${w.length}B $w');
    }
  });

  void send(String wire) {
    sock.send(utf8.encode(wire), bcast, port);
    stdout.writeln('-> ${wire.length}B $wire');
  }

  Future<String?> result(String id, {int secs = 20, bool finalOnly = false}) async {
    try {
      return await heard.stream
          .where((w) => w.startsWith('t:result') && field(w, 'r') == id &&
              (!finalOnly || field(w, 'code') != '202'))
          .first
          .timeout(Duration(seconds: secs));
    } on TimeoutException {
      stdout.writeln('   (no answer to $id in $secs s)');
      return null;
    }
  }

  // Sent again every three seconds until answered, as a phone's
  // advertisement repeats: one datagram on a weak link is easily lost.
  Future<String?> ask(String wire, {int secs = 20, bool finalOnly = false}) async {
    send(wire);
    var n = 0;
    final t = Timer.periodic(const Duration(seconds: 3), (_) {
      if (++n <= 4) sock.send(utf8.encode(wire), bcast, port);
    });
    try {
      return await result(idOf(wire), secs: secs, finalOnly: finalOnly);
    } finally {
      t.cancel();
    }
  }

  // The station's key: from its ask to be claimed, or its identity.
  Future<Uint8List> stationKey() async {
    stdout.writeln('   listening for $to to say who it is (q:owner or t:identity)...');
    final w = await heard.stream
        .where((w) => field(w, 'f') == to && field(w, 'k') != null)
        .first
        .timeout(const Duration(seconds: 130));
    final k = field(w, 'k')!;
    if (NostrKeyGenerator.deriveStationCallsign(k) != to &&
        NostrKeyGenerator.deriveCallsign(k).substring(2) != to.substring(2)) {
      stderr.writeln('$to does not derive from $k');
      exit(1);
    }
    return Uint8List.fromList(unhex(NostrCrypto.decodeNpub(k)));
  }

  String sealed(Uint8List station, String body) {
    final blob = XprsCrypto.encryptFor(d, station, Uint8List.fromList(utf8.encode(body)))!;
    return sign('t:command f:$me d:$to ts:${stamp()} x:${b64u(blob)}', d);
  }

  switch (step) {
    case 'listen':
      await Future.delayed(Duration(seconds: int.parse(arg(argv, 'secs', '60'))));
    case 'claim':
      final w = sign('t:command f:$me d:$to ts:${stamp()} cmd:set owner:$me k:$npub', d);
      await ask(w);
    case 'replay':
      // An old claim: a ts before the one the station accepted last.
      final w = sign('t:command f:$me d:$to ts:${stamp(-3600)} cmd:set owner:$me k:$npub', d);
      await ask(w);
    case 'repeat':
      // The same command three times, as an advertisement repeats.
      final w = sign('t:command f:$me d:$to ts:${stamp()} cmd:set nick:bench', d);
      for (var i = 0; i < 3; i++) {
        send(w);
        await Future.delayed(const Duration(seconds: 2));
      }
      await result(idOf(w), secs: 5);
      await Future.delayed(const Duration(seconds: 14));
      send(w);
      await result(idOf(w), secs: 10);
    case 'wifi':
      final k = await stationKey();
      final body = 'cmd:set\nssid:${arg(argv, 'ssid')}\npass:${arg(argv, 'pass')}';
      final w = sealed(k, body);
      final first = await ask(w);
      if (first != null && field(first, 'code') == '202') {
        await result(idOf(w), secs: 40, finalOnly: true);
      }
    case 'clearpass':
      final w = sign('t:command f:$me d:$to ts:${stamp()} cmd:set pass:${arg(argv, 'pass')}', d);
      await ask(w);
    case 'set':
      final kv = argv.where((a) => a.contains('=') && !a.startsWith('--')).map((a) => a.replaceFirst('=', ':')).join(' ');
      final w = sign('t:command f:$me d:$to ts:${stamp()} cmd:set $kv', d);
      await ask(w, secs: 30);
    case 'zdiag':
      final w = sign('t:command f:$me d:$to ts:${stamp()} cmd:zdiag', d);
      await ask(w);
    case 'rekey':
      final w = sign('t:command f:$me d:$to ts:${stamp()} cmd:set key:new', d);
      final r = await ask(w);
      final k = r == null ? null : field(r, 'k');
      if (k != null) {
        final now = NostrKeyGenerator.deriveStationCallsign(k);
        stdout.writeln('   the new key is $now; waiting for it to answer under r:${idOf(w)}');
        await heard.stream
            .where((x) => x.startsWith('t:result') && field(x, 'r') == idOf(w) &&
                field(x, 'f') == now)
            .first
            .timeout(const Duration(seconds: 90), onTimeout: () {
          stdout.writeln('   (the new key never answered)');
          return '';
        });
      }
    default:
      stderr.writeln('unknown step $step');
  }
  sock.close();
  exit(0);
}
