/*
 * FileSource backed by the content-addressed MediaArchive (media.zx).
 *
 * Lets a serving node answer file-transfer requests with bytes it already holds
 * (received chat media, imported files, pinned content). The file-transfer
 * protocol (FileServeSession) reads whole-file bytes by sha256 through this; the
 * archive deduplicates and stores by the same sha256 id used in file:<sha256>
 * media refs, so "I received this image" automatically means "I can serve it".
 */
import 'dart:typed_data';

import '../../util/media_archive.dart';
import 'file_transfer.dart';

class MediaFileSource implements RangedFileSource {
  final MediaArchive archive;
  MediaFileSource(this.archive);

  @override
  Uint8List? read(Uint8List fileHash) => archive.get(_hex(fileHash));

  /// One piece, sliced by the store. Before this was a [RangedFileSource], every
  /// GET_RANGE from a peer loaded the whole BLOB to cut 64 KiB out of it.
  @override
  Uint8List? readRange(Uint8List fileHash, int offset, int length) =>
      archive.readRange(_hex(fileHash), offset, length);

  /// Everything or nothing (the archive holds whole files), learned from the
  /// size column instead of from the bytes.
  @override
  PieceMask? pieceMask(Uint8List fileHash, int pieceSize) {
    final n = archive.sizeOf(_hex(fileHash));
    return n == null ? null : PieceMask.full(n, pieceSize);
  }

  /// Whether the archive holds [fileHash] (cheap, no blob read).
  bool has(Uint8List fileHash) => archive.has(_hex(fileHash));

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}
