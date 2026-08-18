/*
 * CompositeFileSource — serve bytes from several sources, first hit wins. Lets a
 * node serve content-addressed bytes from the sqlite archive AND from any number
 * of on-disk owner folders (DiskFolderSource) under one FileSource, so disk
 * folders never need to be copied into the archive.
 *
 * It is also the node's PIECE server (docs/torrents.md §8 step 2): a range or a
 * piece-mask query is delegated to whichever child actually holds the file. That
 * delegation is not a nicety — without it, serving one 64 KiB piece of a 4 GB
 * film would fall back to reading all 4 GB into memory in order to slice it.
 */
import 'dart:typed_data';

import 'file_transfer.dart' show FileSource, PieceMask, RangedFileSource;

class CompositeFileSource implements RangedFileSource {
  final List<FileSource> _sources;
  CompositeFileSource(this._sources);

  /// Add/remove sources at runtime (e.g. as owner disk folders are registered).
  void add(FileSource s) => _sources.add(s);
  void remove(FileSource s) => _sources.remove(s);

  @override
  Uint8List? read(Uint8List fileHash) {
    for (final s in _sources) {
      final b = s.read(fileHash);
      if (b != null) return b;
    }
    return null;
  }

  @override
  Uint8List? readRange(Uint8List fileHash, int offset, int length) {
    for (final s in _sources) {
      if (s is RangedFileSource) {
        final b = s.readRange(fileHash, offset, length);
        if (b != null) return b;
      }
    }
    // A child that cannot serve a range still HOLDS the bytes; slicing them is
    // correct, just expensive. An expensive seed beats no seed.
    final whole = read(fileHash);
    if (whole == null) return null;
    if (offset < 0 || offset >= whole.length) return null;
    final end =
        (offset + length > whole.length) ? whole.length : offset + length;
    return Uint8List.sublistView(whole, offset, end);
  }

  @override
  PieceMask? pieceMask(Uint8List fileHash, int pieceSize) {
    for (final s in _sources) {
      if (s is RangedFileSource) {
        final m = s.pieceMask(fileHash, pieceSize);
        if (m != null) return m;
      }
    }
    final whole = read(fileHash);
    if (whole == null) return null;
    return PieceMask.full(whole.length, pieceSize);
  }
}
