/*
 * In-process file-transfer round-trip tests — the regression lock for the file
 * layer over Reticulum. Two FileTransferNodes are wired together with send
 * callbacks that parse + route packets between them (no sockets), exercising the
 * full link handshake + whole-file Resource (GET_FILE) path exactly as on the
 * wire. A whole file rides ONE Resource (segmented/HMU/windowed by the Resource
 * layer), so large files (55 MB, 107 MB) transfer with no size cap.
 */
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// One side of a 2-node loopback: parses raw bytes back into packets and feeds
/// them to its node one at a time (mirrors how the real transport delivers).
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

/// Deterministic pseudo-random bytes of [n] (reproducible across runs).
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

/// A FileSource that holds one file but serves CORRUPTED bytes for it — the
/// assembled content won't hash to the requested id, so the fetcher must reject it.
class _CorruptSource implements FileSource {
  final Uint8List corrupt;
  _CorruptSource(this.corrupt);
  @override
  Uint8List? read(Uint8List fileHash) => corrupt;
}

void main() {
  /// Build provider (holds [providerSource]) + fetcher, wired loopback. Returns
  /// the fetcher node and the provider's public identity to fetch from.
  Future<(FileTransferNode fetcher, RnsIdentity providerPub)> pair(
      FileSource providerSource) async {
    final provId = await RnsIdentity.generate();
    final fetchId = await RnsIdentity.generate();
    final loopProvider = _Loop();
    final loopFetcher = _Loop();
    loopProvider.node = FileTransferNode(
      identity: provId,
      source: providerSource,
      send: (raw) => loopFetcher.deliver(raw),
    );
    loopFetcher.node = FileTransferNode(
      identity: fetchId,
      source: const EmptyFileSource(),
      send: (raw) => loopProvider.deliver(raw),
    );
    final provPub = RnsIdentity.fromPublicKey(provId.getPublicKey());
    return (loopFetcher.node, provPub);
  }

  group('whole-file transfer (GET_FILE, single Resource)', () {
    for (final spec in const [
      ('1 MB', 1024 * 1024),
      ('10 MB', 10 * 1024 * 1024),
      ('55 MB', 55 * 1024 * 1024),
      ('107 MB', 107 * 1024 * 1024), // no size cap (multi-segment Resource)
    ]) {
      test('round-trips ${spec.$1} and verifies', () async {
        final file = _bytes(spec.$2, seed: spec.$2);
        final hash = _sha(file);
        final src = MemoryFileSource()..add(file);
        final (fetcher, provPub) = await pair(src);

        final got = await fetcher.fetch(hash, provPub,
            timeout: const Duration(minutes: 5));
        expect(got, isNotNull, reason: 'fetch returned null for ${spec.$1}');
        expect(got!.length, file.length);
        expect(_sha(got), equals(hash), reason: 'assembled hash mismatch');
      }, timeout: const Timeout(Duration(minutes: 6)));
    }

    test('round-trips an empty file', () async {
      final file = Uint8List(0);
      final hash = _sha(file);
      final src = MemoryFileSource()..add(file);
      final (fetcher, provPub) = await pair(src);
      final got = await fetcher.fetch(hash, provPub);
      expect(got, isNotNull);
      expect(got!.length, 0);
      expect(_sha(got), equals(hash));
    });

    test('returns null when the provider does not hold the file', () async {
      final want = _sha(_bytes(1000, seed: 7));
      final (fetcher, provPub) = await pair(MemoryFileSource());
      final got =
          await fetcher.fetch(want, provPub, timeout: const Duration(seconds: 5));
      expect(got, isNull);
    });

    test('rejects a corrupting provider (content-address check)', () async {
      final real = _bytes(200 * 1024, seed: 99);
      final realHash = _sha(real);
      final corrupt = Uint8List.fromList(real)..[123] ^= 0xff; // flip a byte
      final (fetcher, provPub) = await pair(_CorruptSource(corrupt));
      final got = await fetcher.fetch(realHash, provPub,
          timeout: const Duration(seconds: 10));
      expect(got, isNull, reason: 'tampered bytes must not verify as the id');
    });
  });

  group('resumable downloads', () {
    final M = kMaxEfficientSize; // segment size (1048575)

    // Provider holding [providerSource] + fetcher whose downloads persist to
    // [store] (so a fetch resumes from a pre-seeded partial). Loopback-wired.
    Future<(FileTransferNode fetcher, RnsIdentity providerPub)> pairResumable(
        FileSource providerSource, PartialStore store) async {
      final provId = await RnsIdentity.generate();
      final fetchId = await RnsIdentity.generate();
      final loopProvider = _Loop();
      final loopFetcher = _Loop();
      loopProvider.node = FileTransferNode(
        identity: provId,
        source: providerSource,
        send: (raw) => loopFetcher.deliver(raw),
      );
      loopFetcher.node = FileTransferNode(
        identity: fetchId,
        source: const EmptyFileSource(),
        send: (raw) => loopProvider.deliver(raw),
        partialStore: store,
      );
      return (loopFetcher.node, RnsIdentity.fromPublicKey(provId.getPublicKey()));
    }

    // Pre-seed the first [segs] complete segments of [file] into [store] — exactly
    // what an interrupted download leaves behind.
    Future<void> seed(PartialStore store, Uint8List hash, Uint8List file,
        int segs, int total) async {
      for (var i = 0; i < segs; i++) {
        await store.appendSegment(
            hash, i, Uint8List.sublistView(file, i * M, (i + 1) * M),
            total: total);
      }
    }

    late Directory tmp;
    setUp(() => tmp = Directory.systemTemp.createTempSync('rns_partial'));
    tearDown(() {
      if (tmp.existsSync()) tmp.deleteSync(recursive: true);
    });

    test('resumes from a pre-seeded partial (serves only the tail)', () async {
      final file = _bytes(M * 2 + 40000, seed: 4242); // 3 segments, last short
      final hash = _sha(file);
      final store = FilePartialStore(tmp);
      await seed(store, hash, file, 2, file.length); // first 2 segments held

      final (fetcher, provPub) = await pairResumable(MemoryFileSource()..add(file), store);
      final got =
          await fetcher.fetch(hash, provPub, timeout: const Duration(minutes: 2));

      expect(got, isNotNull);
      expect(got!.length, file.length);
      expect(_sha(got), equals(hash), reason: 'resumed assembly must verify');
      // Partial dropped on success (give the fire-and-forget delete a moment).
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(await store.load(hash), isNull, reason: 'partial cleared on success');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('resume across an exact segment boundary (no short tail)', () async {
      final file = _bytes(M * 4, seed: 7); // exactly 4 full segments
      final hash = _sha(file);
      final store = FilePartialStore(tmp);
      await seed(store, hash, file, 2, file.length);
      final (fetcher, provPub) = await pairResumable(MemoryFileSource()..add(file), store);
      final got =
          await fetcher.fetch(hash, provPub, timeout: const Duration(minutes: 2));
      expect(got, isNotNull);
      expect(_sha(got!), equals(hash));
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('d-guard: a wrong total triggers fallback to a full fetch', () async {
      final file = _bytes(M * 4 + 1000, seed: 11); // 5 segments
      final hash = _sha(file);
      final store = FilePartialStore(tmp);
      // Valid prefix bytes, but claim a wrong total -> the first resumed
      // advertisement's d != stored total -> resume rejected -> restart full.
      await seed(store, hash, file, 2, file.length + 999999);
      final (fetcher, provPub) = await pairResumable(MemoryFileSource()..add(file), store);
      final got =
          await fetcher.fetch(hash, provPub, timeout: const Duration(minutes: 2));
      expect(got, isNotNull, reason: 'must recover via a full fetch');
      expect(_sha(got!), equals(hash));
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('safety net: a wrong-content prefix fails sha then recovers full', () async {
      final file = _bytes(M * 3 + 5000, seed: 21); // 4 segments
      final other = _bytes(M * 3 + 5000, seed: 22); // SAME length, different bytes
      final hash = _sha(file);
      final store = FilePartialStore(tmp);
      // Seed a wrong prefix at the SAME total: d-guard passes, segments serve the
      // real tail, but assembled (wrong prefix + real tail) fails the final sha
      // -> partial discarded -> full re-fetch yields the real file.
      await seed(store, hash, other, 2, file.length);
      final (fetcher, provPub) = await pairResumable(MemoryFileSource()..add(file), store);
      final got =
          await fetcher.fetch(hash, provPub, timeout: const Duration(minutes: 2));
      expect(got, isNotNull);
      expect(_sha(got!), equals(hash), reason: 'final sha safety net recovers');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('sub-1MB file leaves no partial (nothing to resume)', () async {
      final file = _bytes(300 * 1024, seed: 5);
      final hash = _sha(file);
      final store = FilePartialStore(tmp);
      final (fetcher, provPub) = await pairResumable(MemoryFileSource()..add(file), store);
      final got = await fetcher.fetch(hash, provPub);
      expect(got, isNotNull);
      expect(_sha(got!), equals(hash));
      expect(await store.load(hash), isNull);
    });

    test('FilePartialStore: append, load, self-heal torn tail, delete', () async {
      final store = FilePartialStore(tmp);
      final file = _bytes(M * 3, seed: 33);
      final hash = _sha(file);
      await store.appendSegment(hash, 0, Uint8List.sublistView(file, 0, M),
          total: file.length);
      await store.appendSegment(hash, 1, Uint8List.sublistView(file, M, 2 * M),
          total: file.length);
      final rs = await store.load(hash);
      expect(rs, isNotNull);
      expect(rs!.segmentsComplete, 2);
      expect(rs.total, file.length);
      expect(rs.bytes.length, 2 * M);
      expect(rs.bytes, equals(Uint8List.sublistView(file, 0, 2 * M)));

      // Simulate a torn tail (a 3rd segment half-written, meta still says 2).
      final sha = hash.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
      final raf = await File('${tmp.path}/$sha.part').open(mode: FileMode.writeOnlyAppend);
      await raf.writeFrom(Uint8List(12345));
      await raf.close();
      final healed = await store.load(hash);
      expect(healed, isNotNull);
      expect(healed!.bytes.length, 2 * M, reason: 'torn tail truncated to boundary');

      await store.delete(hash);
      expect(await store.load(hash), isNull);
    });

    test('FilePartialStore.gc reclaims by age', () async {
      final store = FilePartialStore(tmp);
      final h = _sha(_bytes(10, seed: 1));
      final file = _bytes(M, seed: 2);
      await store.appendSegment(h, 0, file, total: M * 2);
      expect(await store.load(h), isNotNull);
      await store.gc(maxAge: Duration.zero); // everything is "stale"
      expect(await store.load(h), isNull);
    });
  });
}
