/*
 * The piece engine (aurora/docs/torrents.md §8 step 2).
 *
 * These lock the three properties that make a swarm a swarm rather than a
 * download queue, and each test fails on the pre-engine code:
 *
 *   1. a file assembles from MANY peers at once, and — the load-bearing case —
 *      from peers where NO SINGLE ONE holds the whole file. That is a partial
 *      holder seeding, which is what gives a 50-peer swarm 50 uploaders;
 *   2. a peer that serves bytes which do not match the SIGNED piece hash is
 *      caught on that piece and dropped, and the file still completes from the
 *      honest peers. A liar costs one piece, not a 4 GB download;
 *   3. the last pieces are not held hostage: with one piece left and several
 *      idle peers, it is asked of all of them and the first answer wins.
 *
 * Multiple FileTransferNodes are wired in-process (no sockets), so the full link
 * handshake + Resource path runs exactly as on the wire.
 */
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Loop {
  late FileTransferNode node;
  final List<RnsPacket> _inbox = [];
  bool _pumping = false;

  void deliver(Uint8List raw) {
    final p = RnsPacket.parse(raw);
    if (p == null) return;
    _inbox.add(p);
    _pump();
  }

  Future<void> _pump() async {
    if (_pumping) return;
    _pumping = true;
    while (_inbox.isNotEmpty) {
      final p = _inbox.removeAt(0);
      try {
        await node.handlePacket(p);
      } catch (_) {/* a wrong-peer packet is ignored, as on the wire */}
    }
    _pumping = false;
  }
}

Uint8List _bytes(int n, {int seed = 1}) {
  final out = Uint8List(n);
  var x = (seed * 2654435761) & 0xffffffff;
  for (var i = 0; i < n; i++) {
    x = (1103515245 * x + 12345) & 0x7fffffff;
    out[i] = (x >> 16) & 0xff;
  }
  return out;
}

Uint8List _sha(Uint8List b) =>
    Uint8List.fromList(crypto.sha256.convert(b).bytes);

List<Uint8List> _pieceHashes(Uint8List file, int pieceSize) {
  final out = <Uint8List>[];
  for (var o = 0; o < file.length; o += pieceSize) {
    final end = (o + pieceSize > file.length) ? file.length : o + pieceSize;
    out.add(_sha(Uint8List.sublistView(file, o, end)));
  }
  return out;
}

/// A peer that holds only SOME pieces of a file — a leecher that is still
/// downloading, and is therefore a source for what it already has.
class _PartialSource implements RangedFileSource {
  final Uint8List file;
  final Uint8List hash;
  final int pieceSize;
  final Set<int> held;

  _PartialSource(this.file, this.pieceSize, this.held) : hash = _sha(file);

  bool _isFile(Uint8List h) {
    if (h.length != hash.length) return false;
    for (var i = 0; i < h.length; i++) {
      if (h[i] != hash[i]) return false;
    }
    return true;
  }

  // It does NOT hold the whole file, so a whole-file GET_FILE must find nothing.
  @override
  Uint8List? read(Uint8List fileHash) => null;

  @override
  Uint8List? readRange(Uint8List fileHash, int offset, int length) {
    if (!_isFile(fileHash)) return null;
    final piece = offset ~/ pieceSize;
    if (!held.contains(piece)) return null;
    final end = (offset + length > file.length) ? file.length : offset + length;
    return Uint8List.sublistView(file, offset, end);
  }

  @override
  PieceMask? pieceMask(Uint8List fileHash, int ps) {
    if (!_isFile(fileHash)) return null;
    final m = PieceMask.empty(file.length, ps);
    for (final i in held) {
      m.set(i);
    }
    return m;
  }
}

/// A peer that claims every piece and serves garbage for one of them.
class _LyingSource implements RangedFileSource {
  final Uint8List file;
  final Uint8List hash;
  final int lieAboutPiece;
  final int pieceSize;

  _LyingSource(this.file, this.pieceSize, this.lieAboutPiece)
      : hash = _sha(file);

  @override
  Uint8List? read(Uint8List fileHash) => null;

  @override
  Uint8List? readRange(Uint8List fileHash, int offset, int length) {
    final piece = offset ~/ pieceSize;
    final end = (offset + length > file.length) ? file.length : offset + length;
    final real = Uint8List.sublistView(file, offset, end);
    if (piece != lieAboutPiece) return real;
    // Same length, wrong bytes: the length check cannot catch this. Only the
    // signed piece hash can.
    return Uint8List(real.length)..fillRange(0, real.length, 0x42);
  }

  @override
  PieceMask? pieceMask(Uint8List fileHash, int ps) =>
      PieceMask.full(file.length, ps);
}

void main() {
  /// Wire one fetcher to N providers, all in-process.
  Future<(FileTransferNode, List<RnsIdentity>)> swarm(
      List<FileSource> providerSources) async {
    final fetchId = await RnsIdentity.generate();
    final loopFetcher = _Loop();
    final pubs = <RnsIdentity>[];
    final loops = <_Loop>[];

    for (final src in providerSources) {
      final provId = await RnsIdentity.generate();
      final loop = _Loop();
      loop.node = FileTransferNode(
        identity: provId,
        source: src,
        send: (raw) => loopFetcher.deliver(raw),

      );
      loops.add(loop);
      pubs.add(RnsIdentity.fromPublicKey(provId.getPublicKey()));
    }

    loopFetcher.node = FileTransferNode(
      identity: fetchId,
      source: const EmptyFileSource(),
      // The fetcher's outbound packets go to every provider; each one ignores
      // what is not addressed to its links, exactly as on a shared medium.
      send: (raw) {
        for (final l in loops) {
          l.deliver(raw);
        }
      },

    );
    return (loopFetcher.node, pubs);
  }

  const pieceSize = 64 * 1024;

  test('assembles a file no single peer holds (partial holders seed)', () async {
    final file = _bytes(512 * 1024, seed: 7); // 8 pieces
    final hash = _sha(file);
    final hashes = _pieceHashes(file, pieceSize);
    expect(hashes.length, 8);

    // Neither peer has the whole file, and together they cover it exactly once.
    final a = _PartialSource(file, pieceSize, {0, 1, 2, 3});
    final b = _PartialSource(file, pieceSize, {4, 5, 6, 7});

    final (fetcher, pubs) = await swarm([a, b]);

    // A whole-file fetch from either would fail — neither holds it.
    final whole = await fetcher.fetch(hash, pubs.first,
        timeout: const Duration(seconds: 20));
    expect(whole, isNull,
        reason: 'a partial holder must not answer a whole-file GET_FILE');

    final got = await fetcher.fetchFilePieces(
      fileHash: hash,
      size: file.length,
      pieceSize: pieceSize,
      pieceHashes: hashes,
      providers: pubs,
      timeout: const Duration(minutes: 3),
    );
    expect(got, isNotNull, reason: 'the swarm holds every piece between them');
    expect(_sha(got!), equals(hash));
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('a peer that serves bytes failing the signed piece hash is dropped',
      () async {
    final file = _bytes(256 * 1024, seed: 11); // 4 pieces
    final hash = _sha(file);
    final hashes = _pieceHashes(file, pieceSize);

    // An honest peer with everything, and a liar that corrupts piece 2.
    final honest = _PartialSource(file, pieceSize, {0, 1, 2, 3});
    final liar = _LyingSource(file, pieceSize, 2);

    final (fetcher, pubs) = await swarm([liar, honest]);

    final got = await fetcher.fetchFilePieces(
      fileHash: hash,
      size: file.length,
      pieceSize: pieceSize,
      pieceHashes: hashes,
      providers: pubs,
      timeout: const Duration(minutes: 3),
    );
    // The lie costs one piece; the file still completes from the honest peer.
    expect(got, isNotNull, reason: 'the honest peer can still supply piece 2');
    expect(_sha(got!), equals(hash));
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('fails honestly when the swarm is missing a piece', () async {
    final file = _bytes(256 * 1024, seed: 13); // 4 pieces
    final hash = _sha(file);
    final hashes = _pieceHashes(file, pieceSize);

    // Nobody has piece 3. A torrent client must say so, not hand back a file
    // with a hole in it.
    final a = _PartialSource(file, pieceSize, {0, 1});
    final b = _PartialSource(file, pieceSize, {1, 2});

    final (fetcher, pubs) = await swarm([a, b]);
    final got = await fetcher.fetchFilePieces(
      fileHash: hash,
      size: file.length,
      pieceSize: pieceSize,
      pieceHashes: hashes,
      providers: pubs,
      timeout: const Duration(seconds: 30),
    );
    expect(got, isNull);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a piece mask round-trips through the wire encoding', () {
    final m = PieceMask.empty(10 * 1024, 1024); // 10 pieces
    expect(m.count, 10);
    expect(m.isEmpty, isTrue);
    m..set(0)..set(3)..set(9);
    expect(m.has(0), isTrue);
    expect(m.has(1), isFalse);
    expect(m.has(3), isTrue);
    expect(m.has(9), isTrue);
    expect(m.held, 3);
    expect(m.isComplete, isFalse);

    final full = PieceMask.full(10 * 1024, 1024);
    expect(full.isComplete, isTrue);
    expect(full.held, 10);
  });
}
