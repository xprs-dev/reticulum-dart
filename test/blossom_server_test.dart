import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show sha256;
import 'dart:ffi';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:sqlite3/open.dart';

void main() {
  // CI/dev hosts often ship only the runtime .so.0, not the dev symlink.
  open.overrideFor(OperatingSystem.linux,
      () => DynamicLibrary.open('libsqlite3.so.0'));

  late Directory dir;
  late MediaArchive archive;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('blossom_test');
    archive = MediaArchive.forDirectory(dir.path);
  });

  tearDown(() async {
    await BlossomServer.instance.stop();
    BlossomServer.instance.uploadsEnabled = false;
    archive.close();
    await dir.delete(recursive: true);
  });

  test('serves a stored blob by sha256 and answers the discovery banner',
      () async {
    final data = Uint8List.fromList(utf8.encode('hello blossom'));
    final token = archive.putBytes(data, 'txt');
    final hex = MediaRef.parse(token)!.sha256Hex;

    final ok = await BlossomServer.instance.start(archive, port: 0);
    expect(ok, isTrue);
    final port = BlossomServer.instance.port;

    final client = HttpClient();
    try {
      // Discovery banner.
      final idReq = await client.getUrl(Uri.parse('http://127.0.0.1:$port/'));
      final idRes = await idReq.close();
      final banner = await idRes.transform(utf8.decoder).join();
      expect(idRes.statusCode, HttpStatus.ok);
      expect(banner, contains('aurora-blossom'));

      // Blob fetch, digest-verified.
      final req =
          await client.getUrl(Uri.parse('http://127.0.0.1:$port/$hex.txt'));
      final res = await req.close();
      expect(res.statusCode, HttpStatus.ok);
      final body = await res.fold<BytesBuilder>(
          BytesBuilder(), (b, chunk) => b..add(chunk));
      final bytes = body.takeBytes();
      expect(sha256.convert(bytes).toString(), hex);
      expect(utf8.decode(bytes), 'hello blossom');

      // Unknown hash -> 404.
      final missReq = await client
          .getUrl(Uri.parse('http://127.0.0.1:$port/${'0' * 64}.txt'));
      final missRes = await missReq.close();
      await missRes.drain<void>();
      expect(missRes.statusCode, HttpStatus.notFound);
    } finally {
      client.close(force: true);
    }
  });

  test('upload is rejected when disabled and stored when enabled', () async {
    await BlossomServer.instance.start(archive, port: 0);
    final port = BlossomServer.instance.port;
    final data = Uint8List.fromList(utf8.encode('uploaded blob'));

    Future<int> tryUpload() async {
      final client = HttpClient();
      try {
        final req =
            await client.putUrl(Uri.parse('http://127.0.0.1:$port/upload'));
        req.headers.contentType = ContentType('text', 'plain');
        req.add(data);
        final res = await req.close();
        await res.drain<void>();
        return res.statusCode;
      } finally {
        client.close(force: true);
      }
    }

    expect(await tryUpload(), HttpStatus.forbidden);

    BlossomServer.instance.uploadsEnabled = true;
    expect(await tryUpload(), HttpStatus.ok);
    final hex = sha256.convert(data).toString();
    expect(archive.getMeta(hex), isNotNull);
  });

  test('fetchFrom verifies the digest before archiving', () async {
    final data = Uint8List.fromList(utf8.encode('cross-device blob'));
    final token = archive.putBytes(data, 'txt');
    final hex = MediaRef.parse(token)!.sha256Hex;
    await BlossomServer.instance.start(archive, port: 0);
    final port = BlossomServer.instance.port;

    final other = await Directory.systemTemp.createTemp('blossom_peer');
    final peerArchive = MediaArchive.forDirectory(other.path);
    try {
      final got = await BlossomServer.fetchFrom(
          'http://127.0.0.1:$port', hex, 'txt', peerArchive);
      expect(got, isNotNull);
      expect(MediaRef.parse(got!)!.sha256Hex, hex);
    } finally {
      peerArchive.close();
      await other.delete(recursive: true);
    }
  });
}
