// The near end for the station's request server (xprs-dev/firmware,
// common/xprs_rns/test_rns_serve_host.sh): a real RnsRequestClient talking
// packets as hex lines over stdin and stdout to the C responder, which serves
// the station's `xprs.wapp` destination.
//
//   dart run tool/request_client.dart <server pub hex>
//
// Every line it reads is a packet from the server; every packet it sends is
// a line. It opens a link, runs the requests below and prints one
// `result <name> <value>` line each, then `done`. The C side checks them.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:reticulum/src/services/reticulum/rns_identity.dart';
import 'package:reticulum/src/services/reticulum/rns_packet.dart';
import 'package:reticulum/src/services/reticulum/rns_request.dart';

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String s) => Uint8List.fromList([
      for (var i = 0; i + 1 < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

/// Deterministic bytes, the same as the C side makes them.
Uint8List _bytesOf(int size) {
  final out = Uint8List(size);
  var x = 0x2545F491 ^ size;
  for (var i = 0; i < size; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out[i] = (x >> 16) & 0xff;
  }
  return out;
}

Future<void> main(List<String> args) async {
  final pub = _unhex(args[0]);
  final peer = RnsIdentity.fromPublicKey(pub);
  late RnsRequestClient client;
  client = RnsRequestClient(
    peer: peer,
    appName: 'xprs',
    aspects: const ['wapp'],
    send: (raw) => stdout.writeln(_hex(raw)),
    hasPathForDest: (_) => true,
  );
  stdin.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
    final t = line.trim();
    if (t.isEmpty) return;
    final p = RnsPacket.parse(_unhex(t));
    if (p != null) client.handlePacket(p);
  });
  void result(String name, Object? v) => stdout.writeln('result $name $v');

  final ok = await client.open(timeout: const Duration(seconds: 20));
  result('open', ok);
  if (!ok) {
    stdout.writeln('done');
    exit(1);
  }
  result('link', _hex(client.linkId!));

  // A request and its answer, each one packet.
  final echo = await client.request('/echo', 'hello there');
  result('echo', echo is List<int> ? utf8.decode(echo) : echo);

  // A map, as /xprs/api sends one.
  final api = await client.request('/map', {'m': 'GET', 'p': '/api/services', 'q': {'limit': '20'}});
  result('map', api is List<int> ? utf8.decode(api) : api);

  // Answers as Resources: one segment over several hashmap batches.
  for (final n in [1000, 70000]) {
    final r = await client.request('/big', n, timeout: const Duration(seconds: 120));
    result('big$n', r is List<int> ? '${r.length} ${_hex(crypto.sha256.convert(r).bytes)}' : 'none');
  }

  // A request too large for a packet: it goes as a Resource (an upload).
  final up = _bytesOf(5000);
  final u = await client.request('/echo', up, timeout: const Duration(seconds: 120));
  result('upload', u is List<int> ? '${u.length} ${_hex(crypto.sha256.convert(u).bytes)}' : u);
  result('upload_want', '${up.length} ${_hex(crypto.sha256.convert(up).bytes)}');

  // Past the server's upload cap: answered, not dropped.
  final tooBig = await client.request('/echo', _bytesOf(40000), timeout: const Duration(seconds: 120));
  result('too_large', tooBig);

  // Two segments.
  final r2 = await client.request('/big', 1100000, timeout: const Duration(seconds: 600));
  result('big1100000', r2 is List<int> ? '${r2.length} ${_hex(crypto.sha256.convert(r2).bytes)}' : 'none');

  // A request this server has no handler for: no answer (a timeout).
  final none = await client.request('/nothing', 'x', timeout: const Duration(seconds: 2));
  result('nothing', none);

  client.close();
  stdout.writeln('done');
  await Future<void>.delayed(const Duration(milliseconds: 200));
  exit(0);
}
