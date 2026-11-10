/*
 * A hosted file that arrives in pieces (a film uploaded to a gallery) is
 * stored a part at a time and filed under the hash its bytes have; a wrong
 * hash keeps nothing.
 */
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:reticulum/reticulum.dart';

String _key(List<int> b) =>
    base64Url.encode(crypto.sha256.convert(b).bytes).replaceAll('=', '');

void main() {
  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('media_writer_'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('pieces in, one file out, readable by range', () {
    final archive = MediaArchive.forDirectory(dir.path);
    final data = Uint8List.fromList(List.generate(700000, (i) => i * 13 & 0xff));
    final w = archive.beginHosted('mp4', originPubHex: '', tier: 0, pin: true)!;
    for (var at = 0; at < data.length; at += 50000) {
      w.add(data.sublist(at, (at + 50000).clamp(0, data.length)));
    }
    final key = w.finish(expectKey: _key(data));
    expect(key, _key(data));
    expect(archive.sizeOf(key!), data.length);
    expect(archive.readRange(key, 300000, 10), data.sublist(300000, 300010));
    expect(archive.get(key), data);
    expect(archive.getMeta(key)!.pinned, isTrue);
  });

  test('bytes that do not hash to the reference are not kept', () {
    final archive = MediaArchive.forDirectory(dir.path);
    final w = archive.beginHosted('jpg', originPubHex: '', tier: 2)!;
    w.add(List.filled(1000, 1));
    expect(w.finish(expectKey: _key(List.filled(1000, 2))), isNull);
    expect(archive.has(_key(List.filled(1000, 1))), isFalse);
  });
}
