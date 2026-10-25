// The far end for the station's link and resource receiver (xprs-dev/firmware,
// common/xprs_rns/test_rns_link_host.sh): a real `xprs/files` responder,
// RnsLink.responder + FileServeSession, talking packets as hex lines over
// stdin and stdout. The C test opens a link to it, asks GET_FILE and streams
// the resource; whatever reaches the sink must hash to what this prints.
//
//   dart run tool/files_responder.dart <size> [<size> ...]
//
// Prints, on start:   pub <64 hex>          our identity's public key
//                     file <sha hex> <size> one line per file served
//                     ready
// then answers every packet line with zero or more packet lines, and
// `served <sha hex>` once a file's final proof was accepted.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:reticulum/src/services/files/file_node.dart'
    show kFilesApp, kFilesAspects;
import 'package:reticulum/src/services/files/file_transfer.dart';
import 'package:reticulum/src/services/reticulum/rns_identity.dart';
import 'package:reticulum/src/services/reticulum/rns_link.dart';
import 'package:reticulum/src/services/reticulum/rns_packet.dart';

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String s) => Uint8List.fromList([
      for (var i = 0; i + 1 < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

/// Deterministic bytes: the same size always gives the same file.
Uint8List _fileOf(int size) {
  final out = Uint8List(size);
  var x = 0x9E3779B9 ^ size;
  for (var i = 0; i < size; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out[i] = (x >> 16) & 0xff;
  }
  return out;
}

Future<void> main(List<String> args) async {
  final sizes = args.isEmpty ? [70000] : args.map(int.parse).toList();
  final identity = await RnsIdentity.generate();
  final source = MemoryFileSource();
  stdout.writeln('pub ${_hex(identity.getPublicKey())}');
  for (final s in sizes) {
    final f = _fileOf(s);
    source.add(f);
    stdout.writeln('file ${_hex(crypto.sha256.convert(f).bytes)} $s');
  }
  final filesDest = RnsDestination.hash(identity, kFilesApp, kFilesAspects);
  stdout.writeln('dest ${_hex(filesDest)}');
  stdout.writeln('ready');

  final links = <String, (RnsLink, FileServeSession)>{};
  void send(RnsPacket p) => stdout.writeln(_hex(p.pack()));

  await for (final line
      in stdin.transform(utf8.decoder).transform(const LineSplitter())) {
    final t = line.trim();
    if (t.isEmpty) continue;
    if (t == 'quit') break;
    final p = RnsPacket.parse(_unhex(t));
    if (p == null) {
      stdout.writeln('error unparsable');
      continue;
    }
    if (p.packetType == RnsPacketType.linkRequest &&
        p.destType == RnsDestType.single &&
        _hex(p.destHash) == _hex(filesDest)) {
      final link = await RnsLink.responder(identity, p);
      final id = _hex(link.linkId!);
      final serve = FileServeSession(link, source,
          onServed: (sha, _) => stdout.writeln('serving ${_hex(sha)}'));
      links[id] = (link, serve);
      send(await link.buildProof());
      continue;
    }
    if (p.destType == RnsDestType.link) {
      final e = links[_hex(p.destHash)];
      if (e == null) {
        stdout.writeln('error unknown link');
        continue;
      }
      final (link, serve) = e;
      if (link.status != RnsLinkStatus.active &&
          p.context == RnsContext.lrrtt) {
        link.handleRtt(p);
        stdout.writeln('active');
        continue;
      }
      for (final out in serve.onPacket(p)) {
        send(out);
      }
      continue;
    }
    stdout.writeln('error unexpected packet type ${p.packetType}');
  }
  await stdout.flush();
  exit(0);
}
