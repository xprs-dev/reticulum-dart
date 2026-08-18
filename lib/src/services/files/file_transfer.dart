/*
 * File transfer protocol over an established RNS Link.
 *
 * Transport-agnostic session state machines drive one provider<->fetcher link.
 * They consume inbound RnsPackets (already routed to this link) and return the
 * RnsPackets to send back, so they can be wired to any interface and unit-tested
 * in-process. A whole file rides ONE RNS Resource (the Resource layer segments,
 * windows and HMUs it for arbitrary size); small commands ride a link-encrypted
 * DATA packet with context=none.
 *
 * Wire commands (plaintext of a context-none link DATA):
 *   0x01 GET_FILE      + fileHash(32)              (fetch the whole file)
 *   0x02 GET_FILE_FROM + fileHash(32) + seg(2 BE)  (resume: serve from segment N)
 *   0x81 NOT_FOUND     + fileHash(32)              (provider -> fetcher)
 *
 * GET_FILE_FROM lets a fetcher that already holds segments 0..N-1 (persisted to a
 * PartialStore) ask the provider to start the Resource at segment N. A provider
 * that predates this op simply ignores it; the fetcher detects the silence and
 * falls back to a full GET_FILE (FileTransferNode drives that probe + fallback).
 *
 * A GET_FILE is answered with the file's bytes as a single Resource. Integrity:
 * the Resource verifies each part + each segment; the fetcher additionally checks
 * sha256(assembled) == the requested file id, binding an untrusted transfer to the
 * content the caller asked for.
 *
 * Store-and-forward deposit (a peer asks a host to KEEP a blob it doesn't hold):
 *   client -> host : 0x03 PUT_OFFER  sha(32) size(8 BE) extLen(1) ext pub(32) sig(64)
 *   host -> client : 0x84 PUT_ACCEPT sha(32)            (send the bytes now)
 *   host -> client : 0x82 PUT_REJECT reason(utf8)
 *   client -> host : the blob as an RNS Resource (client = sender, host = receiver)
 *   host -> client : 0x85 PUT_STORED sha(32)
 * The compact auth proves a NOSTR identity authorizes hosting THIS sha: sig is a
 * BIP-340 Schnorr signature by [pub] over sha256("blossom-deposit:"+shaHex).
 */
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../reticulum/rns_link.dart';
import '../reticulum/rns_packet.dart';
import '../reticulum/rns_resource.dart';
import '../reticulum/rns_resource_receiver.dart';
import 'partial_store.dart';
import 'serve_quota.dart';

const int kOpGetFile = 0x01;
const int kOpGetFileFrom = 0x02; // + fileHash(32) + startSegment(2 BE): resume
const int kOpNotFound = 0x81;
const int kOpPutOffer = 0x03;
const int kOpPutReject = 0x82;
const int kOpPutAccept = 0x84;
const int kOpPutStored = 0x85;

// ── The piece engine (aurora/docs/torrents.md §8 step 2) ────────────────────
//
// A whole-file GET_FILE is a download queue, not a swarm: one provider serves
// the whole thing, a partial holder can serve nothing, and a slow peer holds the
// tail hostage. These three ops are what make it a torrent:
//
//   0x07 GET_HAVE  + fileHash(32) + pieceSize(4 BE)
//   0x87 HAVE      + fileHash(32) + pieceSize(4 BE) + pieceCount(4 BE)
//                                 + size(8 BE) + bitfield(ceil(count/8))
//   0x06 GET_RANGE + fileHash(32) + offset(8 BE) + length(4 BE)
//        → the bytes as a Resource, or 0x81 NOT_FOUND when we hold none of it.
//
// HAVE is what lets a leecher seed: it answers with the pieces it actually has,
// so a peer that is 40% done is a source for those 40%. The bitfield is the
// whole reason a 50-peer swarm has 50 uploaders instead of one.
//
// A range's bytes are NOT self-verifying (they are not a whole file, so their
// sha256 is not the file id). The fetcher checks each piece against the SIGNED
// piece hash from the folder's op-log — which is what makes fetching from
// strangers in parallel safe at all. A provider that returns bad bytes is caught
// on the piece, not after the last byte of a 4 GB file.
const int kOpGetRange = 0x06;
const int kOpGetHave = 0x07;
const int kOpHave = 0x87;

/// Which pieces of a file a peer holds. `count` pieces of `pieceSize` bytes
/// (the last one is short), `size` bytes in total.
class PieceMask {
  final int pieceSize;
  final int count;
  final int size;
  final Uint8List bits; // little bit = piece index, LSB-first per byte

  PieceMask({
    required this.pieceSize,
    required this.count,
    required this.size,
    required this.bits,
  });

  /// A peer that holds the whole file.
  factory PieceMask.full(int size, int pieceSize) {
    final count = pieceCountFor(size, pieceSize);
    final bits = Uint8List((count + 7) >> 3);
    for (var i = 0; i < count; i++) {
      bits[i >> 3] |= 1 << (i & 7);
    }
    return PieceMask(
        pieceSize: pieceSize, count: count, size: size, bits: bits);
  }

  factory PieceMask.empty(int size, int pieceSize) {
    final count = pieceCountFor(size, pieceSize);
    return PieceMask(
      pieceSize: pieceSize,
      count: count,
      size: size,
      bits: Uint8List((count + 7) >> 3),
    );
  }

  bool has(int i) =>
      i >= 0 && i < count && (bits[i >> 3] & (1 << (i & 7))) != 0;

  void set(int i) {
    if (i < 0 || i >= count) return;
    bits[i >> 3] |= 1 << (i & 7);
  }

  int get held {
    var n = 0;
    for (var i = 0; i < count; i++) {
      if (has(i)) n++;
    }
    return n;
  }

  bool get isEmpty => held == 0;
  bool get isComplete => held == count;
}

int pieceCountFor(int size, int pieceSize) =>
    pieceSize <= 0 ? 0 : (size + pieceSize - 1) ~/ pieceSize;

/// A source that can serve part of a file, and say which parts it holds.
///
/// Optional: a plain [FileSource] still works (the serve side slices whole-file
/// bytes), but a node that implements this can serve a 4 GB file without reading
/// 4 GB into memory, and — the point — can seed pieces of a file it has not
/// finished downloading.
abstract class RangedFileSource implements FileSource {
  /// Bytes `[offset, offset+length)`, or null when this node cannot serve them.
  Uint8List? readRange(Uint8List fileHash, int offset, int length);

  /// Which pieces of [fileHash] this node holds, or null if it holds none.
  PieceMask? pieceMask(Uint8List fileHash, int pieceSize);
}

/// The canonical message a depositor Schnorr-signs to authorize hosting [shaHex]
/// (returned as 64-char hex, ready for NostrCrypto.schnorrSign/Verify).
String depositAuthMessageHex(String shaHex) =>
    _hex(crypto.sha256.convert(utf8.encode('blossom-deposit:$shaHex')).bytes);

/// A host's decision on an inbound deposit offer.
class DepositVerdict {
  final bool ok;
  final String? reason; // set when !ok
  final int tier; // 0 self / 1 followed / 2 stranger
  final String originPubHex; // depositor's NOSTR pubkey
  final String ext; // file extension to store under
  const DepositVerdict.accept(this.tier, this.originPubHex, this.ext)
      : ok = true,
        reason = null;
  const DepositVerdict.reject(this.reason)
      : ok = false,
        tier = 2,
        originPubHex = '',
        ext = 'bin';
}

/// Where a serving node reads content it holds, by file id (sha256, 32B).
abstract class FileSource {
  /// Whole-file bytes for [fileHash], or null if this node does not hold it.
  Uint8List? read(Uint8List fileHash);
}

/// A [FileSource] that holds nothing (default for a node that only fetches).
class EmptyFileSource implements FileSource {
  const EmptyFileSource();
  @override
  Uint8List? read(Uint8List fileHash) => null;
}

/// An in-memory [FileSource] (tests, small caches). Keyed by lowercase hex.
class MemoryFileSource implements FileSource {
  final Map<String, Uint8List> _byHex = {};
  void add(Uint8List bytes) =>
      _byHex[_hex(crypto.sha256.convert(bytes).bytes)] = bytes;
  @override
  Uint8List? read(Uint8List fileHash) => _byHex[_hex(fileHash)];
}

// ── Provider side ──────────────────────────────────────────────────────────

/// Serves files to one connected fetcher over an active link. One file (one
/// Resource, possibly multi-segment) is served at a time.
class FileServeSession {
  final RnsLink link;
  final FileSource source;
  final ServeQuota? quota; // optional serving budget / anti-abuse guard
  final String requesterId; // best-effort requester key (the link id)
  /// Called once per download a peer starts (when we begin serving a file), with
  /// the 32-byte file hash and the requester key (the link id) — drives the
  /// per-file download metric and the per-folder unique-leecher count.
  final void Function(Uint8List fileHash, String requesterId)? onServed;

  /// Store-and-forward deposit hooks (null = this node does not accept deposits).
  /// [linkIdHex] is the link the offer arrived on: the host maps it back to the
  /// interface (LAN, Bluetooth, LoRa, a hub) because for an Archiver the link IS
  /// the policy — a peer that reached us over a direct link has no route to
  /// anywhere else, and its data dies if we refuse it.
  final DepositVerdict Function(Uint8List sha, int size, String ext,
      String pubHex, String sigHex, String linkIdHex)? onDepositOffer;
  final void Function(
      Uint8List sha, Uint8List bytes, String originPubHex, int tier, String ext)?
      onDepositStore;

  RnsResourceSender? _sender; // current in-flight resource (serving)
  RnsResourceReceiver? _rx; // current in-flight resource (deposit receive)
  Uint8List? _depSha;
  int _depTier = 2;
  String _depOrigin = '';
  String _depExt = 'bin';

  final void Function(String msg)? log;

  FileServeSession(this.link, this.source,
      {this.quota,
      this.requesterId = '',
      this.onServed,
      this.onDepositOffer,
      this.onDepositStore,
      this.log});

  void _abortDeposit() {
    _rx = null;
    _depSha = null;
  }

  /// Process one inbound packet for this link; returns packets to send back.
  List<RnsPacket> onPacket(RnsPacket p) {
    switch (p.context) {
      case RnsContext.resourceReq:
        // Serving: a part request (or an HMU request, 0xFF) for the file we send.
        final s = _sender;
        if (s == null) {
          log?.call('serve: REQ but no active sender');
          return const [];
        }
        final req = link.decrypt(p);
        final out = s.handleRequest(req);
        // Only log HMU (exhausted) requests — low volume, the interesting ones
        // for diagnosing multi-segment/hashmap stalls. Per-part requests are far
        // too frequent to log per-packet.
        if (log != null && req.isNotEmpty && req[0] == 0xFF) {
          final hmu =
              out.where((x) => x.context == RnsContext.resourceHmu).length;
          final parts =
              out.where((x) => x.context == RnsContext.resource).length;
          log!('serve: HMU req seg=${s.segmentIndex} -> hmu=$hmu parts=$parts');
        }
        return out;
      case RnsContext.resourcePrf:
        // Serving: a per-segment proof. Advance + advertise the next segment.
        // RNS sends resource proofs UNENCRYPTED (RNS/Packet.py RESOURCE_PRF), so
        // validate the raw packet data — do NOT link.decrypt() it.
        final s = _sender;
        if (s == null) return const [];
        if (s.validateProof(p.data)) {
          log?.call('serve: PROOF ok complete=${s.complete}');
          if (!s.complete) return [s.advertisementPacket()];
          _sender = null;
        } else {
          log?.call('serve: PROOF INVALID');
        }
        return const [];
      case RnsContext.resourceAdv:
        // Inbound deposit bytes: only when we accepted an offer.
        if (_depSha == null) return const [];
        final rx = RnsResourceReceiver(link);
        _rx = rx;
        if (!rx.ingestAdvertisement(link.decrypt(p))) {
          _abortDeposit();
          return [_putReject('bad advertisement')];
        }
        return _depositAfterReceive(rx);
      case RnsContext.resourceHmu:
        final rx = _rx;
        if (rx == null) return const [];
        rx.ingestHmu(link.decrypt(p));
        return rx.pump();
      case RnsContext.resource:
        final rx = _rx;
        if (rx == null) return const [];
        rx.ingestPart(p.data);
        if (rx.error != null) {
          _abortDeposit();
          return [_putReject('resource error')];
        }
        return _depositAfterReceive(rx);
      case RnsContext.none:
        return _onCommand(link.decrypt(p), link.linkId);
      default:
        return const [];
    }
  }

  // Drive the deposit receiver: keep the window full; on segment completion send
  // the proof; on full completion verify the sha and store.
  List<RnsPacket> _depositAfterReceive(RnsResourceReceiver rx) {
    if (rx.segmentComplete) {
      final out = <RnsPacket>[];
      final prf = rx.proofPacket();
      if (prf != null) out.add(prf);
      if (rx.complete) {
        final bytes = rx.payload!;
        final h = Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
        if (_eq(h, _depSha!)) {
          onDepositStore?.call(_depSha!, bytes, _depOrigin, _depTier, _depExt);
          out.add(_putStored(_depSha!));
        } else {
          out.add(_putReject('hash mismatch'));
        }
        _abortDeposit();
      }
      return out;
    }
    return rx.pump();
  }

  List<RnsPacket> _onCommand(Uint8List cmd, Uint8List? linkId) {
    if (cmd.isEmpty) return const [];
    final op = cmd[0];
    if (op == kOpGetFile && cmd.length >= 1 + 32) {
      final fileHash = Uint8List.sublistView(cmd, 1, 33);
      final bytes = source.read(fileHash);
      if (bytes == null) return [_notFound(fileHash)];
      if (!_allow(fileHash, bytes.length)) return [_notFound(fileHash)];
      onServed?.call(Uint8List.fromList(fileHash), requesterId);
      return _serveResource(bytes, fileHash);
    }
    if (op == kOpGetFileFrom && cmd.length >= 1 + 32 + 2) {
      // Resume: serve the Resource starting at segment N (the fetcher holds 0..N-1).
      final fileHash = Uint8List.sublistView(cmd, 1, 33);
      final startSeg = (cmd[33] << 8) | cmd[34];
      final bytes = source.read(fileHash);
      if (bytes == null) return [_notFound(fileHash)];
      if (!_allow(fileHash, bytes.length)) return [_notFound(fileHash)];
      onServed?.call(Uint8List.fromList(fileHash), requesterId);
      return _serveResource(bytes, fileHash, startSegment: startSeg);
    }
    if (op == kOpGetHave && cmd.length >= 1 + 32 + 4) {
      // "What do you have of this file?" — answered even by a node that holds
      // only some of it, which is exactly the point: a leecher seeds.
      final fileHash = Uint8List.sublistView(cmd, 1, 33);
      final pieceSize = ByteData.sublistView(cmd, 33, 37).getUint32(0, Endian.big);
      if (pieceSize <= 0) return const [];
      final mask = _maskFor(fileHash, pieceSize);
      if (mask == null || mask.isEmpty) return [_notFound(fileHash)];
      return [_have(fileHash, mask)];
    }
    if (op == kOpGetRange && cmd.length >= 1 + 32 + 8 + 4) {
      final fileHash = Uint8List.sublistView(cmd, 1, 33);
      final offset = ByteData.sublistView(cmd, 33, 41).getUint64(0, Endian.big);
      final length = ByteData.sublistView(cmd, 41, 45).getUint32(0, Endian.big);
      if (length <= 0) return [_notFound(fileHash)];
      final bytes = _readRange(fileHash, offset, length);
      if (bytes == null || bytes.isEmpty) return [_notFound(fileHash)];
      if (!_allow(fileHash, bytes.length)) return [_notFound(fileHash)];
      onServed?.call(Uint8List.fromList(fileHash), requesterId);
      // The range rides a Resource like any other payload. It is NOT the whole
      // file, so its sha256 is not the file id — the fetcher verifies it against
      // the signed piece hash instead.
      return _serveResource(bytes, fileHash);
    }
    if (op == kOpPutOffer && cmd.length >= 1 + 32 + 8 + 1) {
      // [0x03][sha32][size8][extLen1][ext][pub32][sig64]
      final sha = Uint8List.sublistView(cmd, 1, 33);
      final size = ByteData.sublistView(cmd, 33, 41).getUint64(0, Endian.big);
      final extLen = cmd[41];
      var o = 42;
      if (cmd.length < o + extLen + 32 + 64) return [_putReject('bad offer')];
      final ext = String.fromCharCodes(cmd.sublist(o, o + extLen));
      o += extLen;
      final pub = Uint8List.sublistView(cmd, o, o + 32);
      o += 32;
      final sig = Uint8List.sublistView(cmd, o, o + 64);
      // The LINK is part of the policy, not a detail: a peer that reached us
      // over Bluetooth or LoRa has no route to anywhere else, and its data dies
      // if we refuse it. The host maps the link to the interface it arrived on.
      final accept = onDepositOffer?.call(
          sha, size, ext, _hex(pub), _hex(sig), linkId == null ? '' : _hex(linkId));
      if (accept == null || !accept.ok) {
        return [_putReject(accept?.reason ?? 'deposits not accepted')];
      }
      _depSha = sha;
      _depTier = accept.tier;
      _depOrigin = accept.originPubHex;
      _depExt = accept.ext.isNotEmpty ? accept.ext : ext;
      return [_putAccept(sha)];
    }
    return const [];
  }

  RnsPacket _putAccept(Uint8List sha) {
    final b = BytesBuilder()
      ..addByte(kOpPutAccept)
      ..add(sha);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _putStored(Uint8List sha) {
    final b = BytesBuilder()
      ..addByte(kOpPutStored)
      ..add(sha);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _putReject(String reason) {
    final b = BytesBuilder()
      ..addByte(kOpPutReject)
      ..add(utf8.encode(reason));
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  // Quota gate: may we serve [bytes] for [fileHash] to this requester now?
  bool _allow(Uint8List fileHash, int bytes) {
    final q = quota;
    if (q == null) return true;
    return q.canServe(requesterId, fileHash, bytes);
  }

  List<RnsPacket> _serveResource(Uint8List payload, Uint8List fileHash,
      {int startSegment = 0}) {
    final s = RnsResourceSender(link, payload);
    final total =
        payload.isEmpty ? 1 : ((payload.length - 1) ~/ kMaxEfficientSize) + 1;
    var from = startSegment;
    if (from > 0 && from < total) {
      s.prepareFrom(from); // resume from segment N
    } else {
      s.prepare();
      from = 0; // out of range -> serve the whole file (client's d-guard catches a mismatch)
    }
    _sender = s;
    // Record only the bytes we actually serve (a resume sends fewer than the full file).
    final served = payload.length - from * kMaxEfficientSize;
    quota?.record(requesterId, fileHash, served < 0 ? 0 : served);
    return [s.advertisementPacket()];
  }

  RnsPacket _notFound(Uint8List fileHash) {
    final b = BytesBuilder()
      ..addByte(kOpNotFound)
      ..add(fileHash);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _have(Uint8List fileHash, PieceMask m) {
    final head = ByteData(4 + 4 + 8);
    head.setUint32(0, m.pieceSize, Endian.big);
    head.setUint32(4, m.count, Endian.big);
    head.setUint64(8, m.size, Endian.big);
    final b = BytesBuilder()
      ..addByte(kOpHave)
      ..add(fileHash)
      ..add(head.buffer.asUint8List())
      ..add(m.bits);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  /// What we hold of this file. A [RangedFileSource] answers precisely (and can
  /// therefore seed a file it is still downloading); a plain source either has
  /// the whole thing or nothing.
  PieceMask? _maskFor(Uint8List fileHash, int pieceSize) {
    final s = source;
    if (s is RangedFileSource) return s.pieceMask(fileHash, pieceSize);
    final bytes = s.read(fileHash);
    if (bytes == null) return null;
    return PieceMask.full(bytes.length, pieceSize);
  }

  /// Serve part of a file WITHOUT reading the whole thing when the source can do
  /// it properly. The fallback slices, which is correct but costs the memory.
  Uint8List? _readRange(Uint8List fileHash, int offset, int length) {
    final s = source;
    if (s is RangedFileSource) return s.readRange(fileHash, offset, length);
    final bytes = s.read(fileHash);
    if (bytes == null) return null;
    if (offset < 0 || offset >= bytes.length) return null;
    final end = (offset + length) > bytes.length ? bytes.length : offset + length;
    return Uint8List.sublistView(bytes, offset, end);
  }
}

// ── Fetcher side ───────────────────────────────────────────────────────────

enum FileFetchState { idle, fetching, done, failed }

/// Fetches one file (by id) from one provider over an active link: GET_FILE, then
/// drive the RnsResourceReceiver (windowed parts, HMU, multi-segment) to
/// completion, verifying sha256(assembled) == the requested id.
class FileFetchSession {
  final RnsLink link;
  final Uint8List wantHash; // requested file id (sha256, 32B)

  /// Resume descriptor (already-held segment-aligned prefix). Null = fetch from 0.
  final ResumeState? resume;

  /// Called when a NON-final segment completes, with its 0-based index and
  /// plaintext, so the owner can persist it to a PartialStore for resume.
  final void Function(int index, Uint8List segData)? onSegment;

  FileFetchState state = FileFetchState.idle;
  String? error;
  Uint8List? result; // assembled, verified file bytes

  /// Set when a resumed transfer was rejected by a resume-integrity guard
  /// (provider serves a different/length-mismatched file, or doesn't honour the
  /// resume) — the owner should discard the partial and retry from segment 0.
  bool resumeRejected = false;

  late final RnsResourceReceiver _rx = RnsResourceReceiver(link);

  FileFetchSession(this.link, this.wantHash, {this.resume, this.onSegment});

  /// Bytes received so far (for a progress display).
  int get receivedBytes => _rx.receivedBytes;

  /// Compact receiver state for stall diagnostics.
  String get debugState => _rx.debugState;

  /// Total payload size once the first advertisement arrives (0 before that).
  int get totalBytes => _rx.totalBytes;

  /// Begin: returns the GET_FILE (or, when resuming, GET_FILE_FROM) packet to send.
  RnsPacket start() {
    state = FileFetchState.fetching;
    final r = resume;
    if (r != null && r.segmentsComplete >= 1) {
      _rx.preloadResume(
          bytes: r.bytes, total: r.total, segmentsComplete: r.segmentsComplete);
      return _cmdGetFileFrom(wantHash, r.segmentsComplete);
    }
    return _cmd(kOpGetFile, wantHash);
  }

  /// Process one inbound packet; returns packets to send back. When [state]
  /// becomes done, [result] holds the verified file; on failed, [error] is set.
  List<RnsPacket> onPacket(RnsPacket p) {
    if (state == FileFetchState.done || state == FileFetchState.failed) {
      return const [];
    }
    if (p.context == RnsContext.none) {
      final cmd = link.decrypt(p);
      if (cmd.isNotEmpty && cmd[0] == kOpNotFound) {
        return _fail('provider does not have the file');
      }
      return const [];
    }
    // resourceAdv / resourceHmu / resource → the shared multi-segment driver.
    final out = _rx.handle(p);
    if (_rx.error != null) {
      // A resume-integrity guard tripped → tell the owner to drop the partial and
      // retry from 0 rather than abandon the file.
      if (_rx.error!.contains('resume')) resumeRejected = true;
      return _fail('resource error: ${_rx.error}');
    }
    // Persist each completed non-final segment for resume.
    final seg = _rx.takeJustCompletedSegment();
    if (seg != null) onSegment?.call(seg.index, seg.data);
    if (_rx.complete) _finish();
    return out;
  }

  /// Re-request stalled parts (call on a stall timer).
  List<RnsPacket> retry() => _rx.retry();

  void _finish() {
    final bytes = _rx.payload;
    if (bytes == null) {
      _fail('no payload after completion');
      return;
    }
    final h = Uint8List.fromList(crypto.sha256.convert(bytes).bytes);
    if (!_eq(h, wantHash)) {
      _fail('assembled file hash != requested id');
      return;
    }
    result = bytes;
    state = FileFetchState.done;
  }

  List<RnsPacket> _fail(String why) {
    error = why;
    state = FileFetchState.failed;
    return const [];
  }

  RnsPacket _cmd(int op, Uint8List arg) {
    final b = BytesBuilder()
      ..addByte(op)
      ..add(arg);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  RnsPacket _cmdGetFileFrom(Uint8List hash, int startSegment) {
    final b = BytesBuilder()
      ..addByte(kOpGetFileFrom)
      ..add(hash)
      ..addByte((startSegment >> 8) & 0xff)
      ..addByte(startSegment & 0xff);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }
}

// ── Piece side (fetcher): one peer, many pieces, over ONE link ───────────────

enum PieceReqState { idle, asking, receiving, done, failed }

/// One peer, held open, answering piece requests.
///
/// The link is the expensive thing (a Curve25519 handshake), so it is opened
/// once and reused for every range this peer serves — a link per piece would
/// cost more in handshakes than the pieces are worth. One request is in flight
/// at a time on a link; parallelism comes from having several PEERS, which is
/// what a swarm is.
class PieceFetchSession {
  final RnsLink link;
  final Uint8List fileHash;

  PieceReqState state = PieceReqState.idle;
  String? error;

  /// The peer's answer to GET_HAVE (null until it arrives; a peer that holds
  /// nothing answers NOT_FOUND and lands in [error]).
  PieceMask? mask;

  /// The bytes of the range currently being fetched, once complete.
  Uint8List? result;

  int _wantLen = 0;
  RnsResourceReceiver? _rx;

  PieceFetchSession(this.link, this.fileHash);

  int get receivedBytes => _rx?.receivedBytes ?? 0;

  /// Ask what this peer holds.
  RnsPacket askHave(int pieceSize) {
    state = PieceReqState.asking;
    final head = ByteData(4)..setUint32(0, pieceSize, Endian.big);
    final b = BytesBuilder()
      ..addByte(kOpGetHave)
      ..add(fileHash)
      ..add(head.buffer.asUint8List());
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  /// Ask for `[offset, offset+length)`.
  RnsPacket askRange(int offset, int length) {
    state = PieceReqState.receiving;
    result = null;
    error = null;
    _wantLen = length;
    _rx = RnsResourceReceiver(link);
    final head = ByteData(12)
      ..setUint64(0, offset, Endian.big)
      ..setUint32(8, length, Endian.big);
    final b = BytesBuilder()
      ..addByte(kOpGetRange)
      ..add(fileHash)
      ..add(head.buffer.asUint8List());
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  /// Feed one inbound packet; returns packets to send back.
  List<RnsPacket> onPacket(RnsPacket p) {
    if (p.context == RnsContext.none) {
      final cmd = link.decrypt(p);
      if (cmd.isEmpty) return const [];
      if (cmd[0] == kOpNotFound) {
        error = 'peer does not have it';
        state = PieceReqState.failed;
        return const [];
      }
      if (cmd[0] == kOpHave && cmd.length >= 1 + 32 + 16) {
        final pieceSize =
            ByteData.sublistView(cmd, 33, 37).getUint32(0, Endian.big);
        final count = ByteData.sublistView(cmd, 37, 41).getUint32(0, Endian.big);
        final size = ByteData.sublistView(cmd, 41, 49).getUint64(0, Endian.big);
        final bits = Uint8List.fromList(cmd.sublist(49));
        if ((count + 7) >> 3 > bits.length) {
          error = 'short bitfield';
          state = PieceReqState.failed;
          return const [];
        }
        mask = PieceMask(
            pieceSize: pieceSize, count: count, size: size, bits: bits);
        state = PieceReqState.done;
      }
      return const [];
    }
    final rx = _rx;
    if (rx == null) return const [];
    final out = rx.handle(p);
    if (rx.error != null) {
      error = 'resource error: ${rx.error}';
      state = PieceReqState.failed;
      return const [];
    }
    if (rx.complete) {
      final bytes = rx.payload;
      if (bytes == null || bytes.length != _wantLen) {
        // A peer that answers a range with the wrong number of bytes is either
        // broken or lying. Either way it is not a source for this range.
        error = 'range length mismatch '
            '(${bytes?.length ?? 0} != $_wantLen)';
        state = PieceReqState.failed;
        return out;
      }
      result = bytes;
      state = PieceReqState.done;
    }
    return out;
  }

  List<RnsPacket> retry() => _rx?.retry() ?? const [];
}

// ── Deposit side (client asks a host to keep a blob) ─────────────────────────

enum FileDepositState { idle, offered, sending, done, failed }

/// Deposits one blob to a host over an active link: offer (with compact auth),
/// then on accept stream the bytes as an RNS Resource, then await PUT_STORED.
class FileDepositSession {
  final RnsLink link;
  final Uint8List sha; // sha256(bytes), 32B
  final Uint8List bytes;
  final String ext;
  final Uint8List pub; // depositor NOSTR pubkey, 32B (x-only)
  final Uint8List sig; // Schnorr sig over depositAuthMessageHex(shaHex), 64B

  FileDepositState state = FileDepositState.idle;
  String? error;
  RnsResourceSender? _sender;

  FileDepositSession(this.link, this.sha, this.bytes, this.ext, this.pub, this.sig);

  /// Begin: returns the PUT_OFFER packet to send.
  RnsPacket start() {
    state = FileDepositState.offered;
    final extB = ascii.encode(ext);
    final b = BytesBuilder()
      ..addByte(kOpPutOffer)
      ..add(sha);
    final sz = ByteData(8)..setUint64(0, bytes.length, Endian.big);
    b
      ..add(sz.buffer.asUint8List())
      ..addByte(extB.length)
      ..add(extB)
      ..add(pub)
      ..add(sig);
    return link.encrypt(b.toBytes(), context: RnsContext.none);
  }

  List<RnsPacket> onPacket(RnsPacket p) {
    if (state == FileDepositState.done || state == FileDepositState.failed) {
      return const [];
    }
    switch (p.context) {
      case RnsContext.none:
        final cmd = link.decrypt(p);
        if (cmd.isEmpty) return const [];
        if (cmd[0] == kOpPutAccept) {
          // Host accepted — stream the bytes as a Resource.
          final s = RnsResourceSender(link, bytes);
          s.prepare();
          _sender = s;
          state = FileDepositState.sending;
          return [s.advertisementPacket()];
        }
        if (cmd[0] == kOpPutReject) {
          return _fail(utf8.decode(cmd.sublist(1), allowMalformed: true));
        }
        if (cmd[0] == kOpPutStored) {
          state = FileDepositState.done;
          return const [];
        }
        return const [];
      case RnsContext.resourceReq:
        final s = _sender;
        if (s == null) return const [];
        return s.handleRequest(link.decrypt(p));
      case RnsContext.resourcePrf:
        final s = _sender;
        if (s == null) return const [];
        // RNS resource proofs are UNENCRYPTED — validate raw p.data.
        if (s.validateProof(p.data) && !s.complete) {
          return [s.advertisementPacket()]; // next segment
        }
        return const []; // success is confirmed by PUT_STORED
      default:
        return const [];
    }
  }

  List<RnsPacket> _fail(String why) {
    error = why;
    state = FileDepositState.failed;
    return const [];
  }
}

bool _eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
