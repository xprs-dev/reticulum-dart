/*
 * Resumable-download persistence (generic, transport-agnostic).
 *
 * A content-addressed fetch (FileTransferNode.fetch / resolveAndFetch) splits a
 * file into deterministic, content-addressed segments of kMaxEfficientSize bytes
 * (the RNS Resource segment size). Every completed NON-final segment is exactly
 * `bytes[i*kMaxEfficientSize : (i+1)*kMaxEfficientSize]`, hash-verified before it
 * is accepted, so N completed segments are always exactly the first
 * `N*kMaxEfficientSize` bytes of the file — safe to persist incrementally and
 * resume on a fresh link (even after an app restart).
 *
 * A [PartialStore] holds those segment-aligned prefixes keyed by the file's
 * sha256. The default [FilePartialStore] is file-based (NOT sqlite — partials can
 * be many MB/GB and would be pathological as blob rows): one `<sha>.part` of raw
 * bytes plus a tiny `<sha>.part.meta` JSON sidecar.
 */
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../reticulum/rns_resource.dart' show kMaxEfficientSize;

/// A resumable partial: the already-held, segment-aligned prefix of a file.
class ResumeState {
  /// Plaintext of the held segments — exactly [segmentsComplete] * kMaxEfficientSize bytes.
  final Uint8List bytes;

  /// Full payload size we resumed from (the d-guard: a provider advertising a
  /// different total is a different file and the resume is abandoned).
  final int total;

  /// Number of complete (non-final) segments held; always >= 1 for a usable resume.
  final int segmentsComplete;

  /// File extension hint (carried through so a re-archive keeps the right type).
  final String ext;

  const ResumeState({
    required this.bytes,
    required this.total,
    required this.segmentsComplete,
    required this.ext,
  });
}

/// Persists segment-aligned partial downloads for resume. Generic: every
/// FileTransferNode fetch consumer (media, folders, wapp store, updates,
/// profiles) benefits without app-specific code.
abstract class PartialStore {
  /// Resume state for [fileHash], or null if there is no usable partial.
  /// Implementations MUST self-heal a torn tail (truncate to the last clean
  /// `segmentsComplete * kMaxEfficientSize` boundary) and return null when
  /// nothing usable remains.
  Future<ResumeState?> load(Uint8List fileHash);

  /// Append a just-completed, hash-verified NON-final segment. [index] is 0-based
  /// and must equal the current segmentsComplete (segments arrive in order).
  Future<void> appendSegment(Uint8List fileHash, int index, Uint8List segData,
      {required int total, String ext});

  /// Drop the partial (on full success, or on a resume-integrity failure).
  Future<void> delete(Uint8List fileHash);

  /// Reclaim stale partials by age and/or a total-bytes budget (LRU by mtime).
  Future<void> gc({Duration? maxAge, int? maxBytes});
}

/// File-based [PartialStore]: `<dir>/<shaHex>.part` (raw bytes) +
/// `<dir>/<shaHex>.part.meta` (JSON {total, segmentsComplete, ext, updatedAt}).
class FilePartialStore implements PartialStore {
  final Directory dir;
  FilePartialStore(this.dir);

  String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  File _part(String sha) => File('${dir.path}/$sha.part');
  File _meta(String sha) => File('${dir.path}/$sha.part.meta');

  Future<void> _ensureDir() async {
    if (!await dir.exists()) await dir.create(recursive: true);
  }

  @override
  Future<ResumeState?> load(Uint8List fileHash) async {
    final sha = _hex(fileHash);
    try {
      final meta = _meta(sha);
      final part = _part(sha);
      if (!await meta.exists() || !await part.exists()) return null;
      final m = jsonDecode(await meta.readAsString()) as Map<String, dynamic>;
      final segs = (m['segmentsComplete'] as num?)?.toInt() ?? 0;
      final total = (m['total'] as num?)?.toInt() ?? 0;
      final ext = (m['ext'] as String?) ?? 'bin';
      if (segs < 1) {
        await delete(fileHash);
        return null;
      }
      final want = segs * kMaxEfficientSize;
      final have = await part.length();
      if (have < want) {
        // Torn/incomplete .part for the claimed segment count — unusable as-is.
        await delete(fileHash);
        return null;
      }
      if (have > want) {
        // Self-heal a torn tail (a segment was being written when we crashed):
        // truncate back to the last clean segment boundary.
        final raf = await part.open(mode: FileMode.append);
        await raf.truncate(want);
        await raf.close();
      }
      final bytes = await part.openRead(0, want).fold<BytesBuilder>(
          BytesBuilder(), (b, chunk) => b..add(chunk));
      return ResumeState(
          bytes: bytes.toBytes(),
          total: total,
          segmentsComplete: segs,
          ext: ext);
    } catch (_) {
      // Any corruption -> drop it and start clean.
      try {
        await delete(fileHash);
      } catch (_) {}
      return null;
    }
  }

  @override
  Future<void> appendSegment(Uint8List fileHash, int index, Uint8List segData,
      {required int total, String ext = 'bin'}) async {
    final sha = _hex(fileHash);
    await _ensureDir();
    final part = _part(sha);
    // Segments arrive in order; index must continue the held prefix exactly.
    final expectedAt = index * kMaxEfficientSize;
    final raf = await part.open(mode: FileMode.writeOnlyAppend);
    try {
      final len = await raf.length();
      if (len != expectedAt) {
        // Out-of-order / gap (shouldn't happen — segments complete sequentially).
        // Don't corrupt the prefix; leave the partial as-is for a clean retry.
        return;
      }
      await raf.setPosition(expectedAt);
      await raf.writeFrom(segData);
      await raf.flush();
    } finally {
      await raf.close();
    }
    await _writeMeta(sha, total: total, segmentsComplete: index + 1, ext: ext);
  }

  Future<void> _writeMeta(String sha,
      {required int total,
      required int segmentsComplete,
      required String ext}) async {
    final tmp = File('${dir.path}/$sha.part.meta.tmp');
    await tmp.writeAsString(jsonEncode({
      'total': total,
      'segmentsComplete': segmentsComplete,
      'ext': ext,
      'updatedAt': DateTime.now().millisecondsSinceEpoch,
    }));
    await tmp.rename(_meta(sha).path); // atomic replace
  }

  @override
  Future<void> delete(Uint8List fileHash) async {
    final sha = _hex(fileHash);
    for (final f in [_part(sha), _meta(sha), File('${dir.path}/$sha.part.meta.tmp')]) {
      try {
        if (await f.exists()) await f.delete();
      } catch (_) {}
    }
  }

  @override
  Future<void> gc({Duration? maxAge, int? maxBytes}) async {
    if (!await dir.exists()) return;
    final entries = <({String sha, int updatedAt, int bytes})>[];
    await for (final e in dir.list()) {
      if (e is! File || !e.path.endsWith('.part.meta')) continue;
      final name = e.uri.pathSegments.last; // <sha>.part.meta
      final sha = name.substring(0, name.length - '.part.meta'.length);
      try {
        final m = jsonDecode(await e.readAsString()) as Map<String, dynamic>;
        final updatedAt = (m['updatedAt'] as num?)?.toInt() ?? 0;
        final bytes = await _part(sha).exists() ? await _part(sha).length() : 0;
        entries.add((sha: sha, updatedAt: updatedAt, bytes: bytes));
      } catch (_) {
        // Unreadable meta -> reclaim it.
        await _deleteByHex(sha);
      }
    }
    final now = DateTime.now().millisecondsSinceEpoch;
    var kept = <({String sha, int updatedAt, int bytes})>[];
    for (final en in entries) {
      if (maxAge != null && now - en.updatedAt > maxAge.inMilliseconds) {
        await _deleteByHex(en.sha);
      } else {
        kept.add(en);
      }
    }
    if (maxBytes != null) {
      var totalBytes = kept.fold<int>(0, (a, b) => a + b.bytes);
      if (totalBytes > maxBytes) {
        kept.sort((a, b) => a.updatedAt.compareTo(b.updatedAt)); // oldest first
        for (final en in kept) {
          if (totalBytes <= maxBytes) break;
          await _deleteByHex(en.sha);
          totalBytes -= en.bytes;
        }
      }
    }
  }

  Future<void> _deleteByHex(String sha) async {
    for (final f in [_part(sha), _meta(sha), File('${dir.path}/$sha.part.meta.tmp')]) {
      try {
        if (await f.exists()) await f.delete();
      } catch (_) {}
    }
  }
}
