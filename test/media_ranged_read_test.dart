/*
 * Serving media reads a piece, not the file.
 *
 * MediaFileSource was a plain FileSource, so every GET_RANGE or GET_HAVE a peer
 * sent made the archive load the whole BLOB (up to 16 MB) to cut 64 KiB out of
 * it or to learn its length — a swarm asking 256 pieces of one file was about
 * 4 GB of reads (audit 2026-11-04, docs/performance.md 8.9). It is a
 * RangedFileSource now: SQLite slices the BLOB and the size comes from its
 * column.
 */
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:reticulum/reticulum.dart';

void main() {

  late Directory dir;
  setUp(() => dir = Directory.systemTemp.createTempSync('media_ranged_'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('ranges and the piece mask come from SQL, and match the bytes', () {
    final archive = MediaArchive.forDirectory(dir.path);
    final data = Uint8List.fromList(List.generate(300000, (i) => i * 7 & 0xff));
    archive.putBytes(data, 'bin');
    final hash = Uint8List.fromList(crypto.sha256.convert(data).bytes);
    final src = MediaFileSource(archive);

    expect(src, isA<RangedFileSource>());
    expect(src.readRange(hash, 0, 10), data.sublist(0, 10));
    expect(src.readRange(hash, 65536, 65536), data.sublist(65536, 131072));
    // A range running past the end is cut at the end, as the fallback did.
    expect(src.readRange(hash, 299990, 100), data.sublist(299990));
    expect(src.readRange(hash, 300000, 10), isNull);

    final mask = src.pieceMask(hash, 65536)!;
    final full = PieceMask.full(data.length, 65536);
    expect(mask.bits, full.bits);

    final absent = Uint8List(32);
    expect(src.readRange(absent, 0, 10), isNull);
    expect(src.pieceMask(absent, 65536), isNull);
  });
}
