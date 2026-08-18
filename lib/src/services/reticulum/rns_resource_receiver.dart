/*
 * RNS Resource — receiver side (wire-compatible, RNS 1.3.5 — RNS/Resource.py).
 *
 * Counterpart to RnsResourceSender. Handles arbitrary-size transfers: a resource
 * arrives as one or more SEGMENTS (linked by original_hash + segment_index/
 * total_segments); within a segment, parts are pulled under a sliding flow-control
 * window, and the per-part hashmap is extended on demand via HashMap-Update (HMU).
 *
 * Per segment the receiver:
 *   1. parses the RESOURCE_ADV (msgpack): transfer size, part count, resource
 *      hash, map-random, segment index/total, and the first hashmap batch;
 *   2. keeps the request window full ([pump]) — requesting missing parts whose
 *      map-hash it knows, and prefetching more hashmap via HMU when it runs low;
 *   3. ingests RESOURCE parts (raw slices of the once-encrypted stream), matching
 *      each to its index by map_hash = full_hash(part + map_random)[:4];
 *   4. once all parts are in, reassembles + token-decrypts the segment, strips the
 *      4-byte stream random, verifies full_hash(seg + map_random) == resource_hash,
 *      appends the segment to the payload and emits a RESOURCE_PRF proof;
 *   5. after the last segment, exposes the full assembled [payload].
 */
import 'dart:math' as math;
import 'dart:typed_data';

import 'rns_crypto.dart';
import 'rns_link.dart';
import 'rns_packet.dart';

const int _mapHashLen = 4;
const int _randomHashSize = 4;
const int _hashLen = 32;
const int _hashmapExhausted = 0xFF;
const int _hashmapNotExhausted = 0x00;

// Adaptive flow-control window, matching RNS/Resource.py. The window is the
// number of parts kept in flight. It starts small and grows toward _windowMax
// each time a full window arrives with nothing left outstanding; on a stall it
// shrinks. _windowMax itself ramps from "slow" to "fast" after a few clean
// rounds (RNS's fast-rate detection), so a healthy link reaches 75 in flight
// while a lossy one stays conservative — instead of blindly over-requesting.
const int _windowStart = 4; // Resource.WINDOW
const int _windowMin0 = 2; // Resource.WINDOW_MIN
const int _windowMaxSlow = 10; // Resource.WINDOW_MAX_SLOW
const int _windowMaxFast = 75; // Resource.WINDOW_MAX_FAST
const int _windowFlexibility = 4; // Resource.WINDOW_FLEXIBILITY
const int _fastRateThreshold = _windowMaxSlow - _windowStart - 2; // 4

// Map-hashes carried per RESOURCE_REQ / HMU batch. FIXED at 74 — RNS's
// ResourceAdvertisement.HASHMAP_MAX_LEN is a class constant from the DEFAULT
// MTU, NOT the per-link negotiated MTU (MTU discovery scales the part SDU, not
// the hashmap batch). Both ends use 74 so HMU segment boundaries stay aligned.
const int _reqBatch = 74;

/// Receiver-side state machine for one inbound Resource (possibly multi-segment).
class RnsResourceReceiver {
  final RnsLink link;

  // Whole-resource state.
  int _totalSegments = 1;
  int _segIndex = 0; // 0-based segment currently being received
  Uint8List _originalHash = Uint8List(0);
  final BytesBuilder _assembled = BytesBuilder(); // completed segments' plaintext

  // Resume state (set by [preloadResume] before the first advertisement). On a
  // resumed transfer the first advertisement we see is segment > 1, so we adopt
  // its original_hash / total_segments instead of treating it as a fresh start,
  // and we DON'T clear the preloaded [_assembled]. _resumeFromSegment is the
  // number of segments already held (the 0-based index of the first segment we
  // expect to receive); _expectedTotal is the full payload size we resumed from,
  // used to reject a provider serving a different-length file.
  int _resumeFromSegment = -1;
  int _expectedTotal = 0;

  // The plaintext of the just-completed segment + its 0-based index, surfaced so
  // the owner can persist completed segments for resume (see takeJustCompletedSegment).
  Uint8List? _lastSegData;
  int _lastSegIndex = -1;

  // Current-segment state.
  int _n = 0; // parts in this segment
  int _transferSize = 0; // encrypted stream size
  int _dataSize = 0; // segment plaintext size (advisory)
  Uint8List _resourceHash = Uint8List(0); // 32B
  Uint8List _mapRandom = Uint8List(0); // 4B
  bool _encrypted = true;
  final List<Uint8List?> _mapHashes = []; // index -> 4B map hash (null = unknown)
  int _knownHashes = 0; // contiguous count of known map-hashes (from 0)
  bool _hmuOutstanding = false;
  final Map<String, int> _hashIndex = {}; // map-hash hex -> index (known parts)
  final Map<int, Uint8List> _parts = {}; // index -> raw part bytes
  final Set<int> _outstanding = {}; // requested, not yet received

  // Adaptive window state (see constants above).
  int _window = _windowStart;
  int _windowMin = _windowMin0;
  int _windowMax = _windowMaxSlow;
  int _fastRounds = 0;

  bool _segmentComplete = false;
  Uint8List? _pendingProof; // proof for the just-completed segment
  Uint8List? _payload; // full assembled plaintext (all segments)
  bool _complete = false;
  String? _error;

  RnsResourceReceiver(this.link);

  bool get complete => _complete;
  bool get segmentComplete => _segmentComplete;
  String? get error => _error;
  Uint8List? get payload => _payload;
  int get expectedParts => _n;
  int get receivedParts => _parts.length;

  /// Compact internal state for stall diagnostics.
  String get debugState => 'seg=${_segIndex + 1}/$_totalSegments '
      'parts=${_parts.length}/$_n known=$_knownHashes '
      'win=$_window(min=$_windowMin,max=$_windowMax) mtu=${link.mtu} '
      'out=${_outstanding.length} hmu=$_hmuOutstanding done=$_segmentComplete';

  /// Received plaintext bytes so far (completed segments + current segment's
  /// received parts, approximate), for a progress display.
  int get receivedBytes {
    var n = _assembled.length;
    final sdu = link.resourceSdu;
    n += _parts.length * sdu; // approximate (last part may be short)
    return n;
  }

  /// The resource's TOTAL payload size (all segments), known from the first
  /// advertisement's `d` field; 0 until then. Enables a real progress percentage.
  int get totalBytes => _dataSize;

  /// Seed a resumed transfer: [bytes] is the plaintext of the already-held
  /// segments (exactly [segmentsComplete] * kMaxEfficientSize bytes), [total] the
  /// full payload size we resumed from. Call BEFORE feeding the first (resumed)
  /// advertisement; the receiver then appends segments [segmentsComplete]..end.
  void preloadResume(
      {required Uint8List bytes,
      required int total,
      required int segmentsComplete}) {
    _assembled.clear();
    _assembled.add(bytes);
    _resumeFromSegment = segmentsComplete;
    _expectedTotal = total;
  }

  /// The plaintext of the most recently completed NON-final segment and its
  /// 0-based index, then clears it. Returns null when nothing new completed (or
  /// the completed segment was the final one — that is exposed via [payload]).
  /// Lets the owner persist completed segments for resume without this state
  /// machine knowing about storage.
  ({int index, Uint8List data})? takeJustCompletedSegment() {
    final d = _lastSegData;
    if (d == null) return null;
    _lastSegData = null;
    return (index: _lastSegIndex, data: d);
  }

  /// Parse a link-decrypted RESOURCE_ADV and set up the next segment. Returns
  /// false on a malformed advertisement (the caller drops the resource). For an
  /// empty segment (n == 0) the segment completes immediately.
  bool ingestAdvertisement(Uint8List advPlaintext) {
    try {
      final m = _MsgpackDecoder(advPlaintext).decode();
      if (m is! Map) return _fail('advertisement not a map');
      _transferSize = _asInt(m['t']);
      _dataSize = _asInt(m['d']);
      _n = _asInt(m['n']);
      _resourceHash = _asBin(m['h']);
      _mapRandom = _asBin(m['r']);
      final origin = _asBin(m['o']);
      final segIndex = _asInt(m['i']); // 1-based
      final segTotal = _asInt(m['l']);
      final flags = _asInt(m['f']);
      _encrypted = (flags & 0x01) != 0;
      final hashmap = _asBin(m['m']);
      if (_n < 0 ||
          _resourceHash.length != _hashLen ||
          _mapRandom.length != _randomHashSize) {
        return _fail('advertisement fields invalid');
      }
      if (segIndex <= 1) {
        _originalHash = origin;
        _totalSegments = segTotal < 1 ? 1 : segTotal;
        _assembled.clear();
      } else if (_originalHash.isEmpty) {
        // First advertisement of a RESUMED transfer (segment > 1). Adopt the
        // sender's original_hash / total_segments and KEEP the preloaded bytes,
        // after verifying the provider continues the SAME file from where we left
        // off. A mismatch fails the receiver, so the owner discards the partial
        // and falls back to a full fetch from segment 0.
        if (_resumeFromSegment < 0) {
          return _fail('unexpected mid-stream segment without resume');
        }
        if (_expectedTotal > 0 && _dataSize != _expectedTotal) {
          return _fail('resume total mismatch'); // different-length file
        }
        if (segIndex - 1 != _resumeFromSegment) {
          return _fail('resume segment misaligned');
        }
        _originalHash = origin;
        _totalSegments = segTotal < 1 ? 1 : segTotal;
      } else if (!RnsCrypto.constantTimeEquals(origin, _originalHash)) {
        return _fail('segment original_hash mismatch');
      }
      _segIndex = segIndex - 1;

      // Reset current-segment state.
      _mapHashes
        ..clear()
        ..addAll(List<Uint8List?>.filled(_n, null));
      _hashIndex.clear();
      _parts.clear();
      _outstanding.clear();
      _knownHashes = 0;
      _hmuOutstanding = false;
      _segmentComplete = false;
      _pendingProof = null;
      // Reset the adaptive flow-control window for the new segment. In RNS each
      // segment is a fresh Resource that starts at WINDOW and re-ramps; carrying
      // the window/min/max across segments lets them degenerate over a long
      // multi-segment transfer (window_min creeps up, window_max creeps down)
      // until throughput collapses and the sender times the segment out.
      _window = _windowStart;
      _windowMin = _windowMin0;
      _windowMax = _windowMaxSlow;
      _fastRounds = 0;

      // Fill the first hashmap batch from the advertisement.
      final firstCount = math.min(hashmap.length ~/ _mapHashLen, _n);
      for (var i = 0; i < firstCount; i++) {
        _setHash(i,
            Uint8List.sublistView(hashmap, i * _mapHashLen, (i + 1) * _mapHashLen));
      }
      _knownHashes = firstCount;

      if (_n == 0) _finishSegment(); // empty segment
      return true;
    } catch (e) {
      return _fail('advertisement parse error: $e');
    }
  }

  void _setHash(int i, Uint8List h) {
    final copy = Uint8List.fromList(h);
    _mapHashes[i] = copy;
    _hashIndex[_hex(copy)] = i;
  }

  /// High-level driver: feed an inbound resource-related packet (resourceAdv /
  /// resourceHmu / resource). Returns the packets to send back (window + HMU
  /// requests, and a per-segment proof when a segment completes). After it, check
  /// [complete] (then [payload] holds the bytes) or [error]. Non-resource packets
  /// return []. The same receiver instance must be reused across all segments.
  List<RnsPacket> handle(RnsPacket p) {
    switch (p.context) {
      case RnsContext.resourceAdv:
        if (!ingestAdvertisement(link.decrypt(p))) return const [];
        return _drive();
      case RnsContext.resourceHmu:
        ingestHmu(link.decrypt(p));
        return pump();
      case RnsContext.resource:
        ingestPart(p.data);
        return _drive();
      default:
        return const [];
    }
  }

  List<RnsPacket> _drive() {
    if (_error != null) return const [];
    if (_segmentComplete) {
      final prf = proofPacket();
      return prf == null ? const [] : [prf];
    }
    return pump();
  }

  /// Packets to send now to keep the transfer moving: part requests filling the
  /// window, plus an HMU request when known hashmap is running low. Call after
  /// every inbound advertisement / HMU / part. Returns [] when nothing to do
  /// right now (waiting on in-flight parts) or the segment is complete.
  List<RnsPacket> pump() {
    if (_complete || _segmentComplete || _n == 0) return const [];
    final out = <RnsPacket>[];

    // Prefetch more hashmap if we're about to run out of known parts to request.
    if (_knownHashes < _n && !_hmuOutstanding) {
      final knownNotReceived = _knownHashes - _parts.length;
      if (knownNotReceived < _window) {
        // We only ask for more hashmap at a HASHMAP_MAX_LEN boundary (RNS
        // sequences HMU by the last known map-hash, which must land on a batch
        // edge). _knownHashes is always a multiple of the batch size here (the
        // advertisement carries the first batch; each HMU adds a full batch).
        if (_knownHashes > 0 && _knownHashes % _reqBatch == 0) {
          _hmuOutstanding = true;
          out.add(_hmuRequest());
        }
      }
    }

    // Fill the part window from known, missing, not-outstanding indices.
    final capacity = _window - _outstanding.length;
    if (capacity > 0) {
      final pick = <int>[];
      for (var i = 0; i < _knownHashes && pick.length < capacity; i++) {
        if (!_parts.containsKey(i) && !_outstanding.contains(i)) pick.add(i);
      }
      for (var off = 0; off < pick.length; off += _reqBatch) {
        final batch =
            pick.sublist(off, math.min(off + _reqBatch, pick.length));
        _outstanding.addAll(batch);
        out.add(_partRequest(batch));
      }
    }
    return out;
  }

  /// Re-request anything still missing (call on a stall timer): drop outstanding
  /// marks so [pump] re-issues requests for parts that never arrived.
  List<RnsPacket> retry() {
    if (_complete || _segmentComplete) return const [];
    _shrinkWindow(); // a stall means we were too aggressive — back off
    _outstanding.clear();
    _hmuOutstanding = false;
    return pump();
  }

  // Grow the window after a clean round; ramp _windowMax to fast after a few.
  void _growWindow() {
    if (_window < _windowMax) {
      _window++;
      if ((_window - _windowMin) > (_windowFlexibility - 1)) _windowMin++;
    }
    if (_fastRounds < _fastRateThreshold) {
      _fastRounds++;
      if (_fastRounds == _fastRateThreshold) _windowMax = _windowMaxFast;
    }
  }

  // Shrink the window on a stall/timeout (RNS watchdog), and reset the fast-rate
  // counter so _windowMax has to be re-earned.
  void _shrinkWindow() {
    if (_window > _windowMin) {
      _window--;
      if (_windowMax > _windowMin) {
        _windowMax--;
        if ((_windowMax - _window) > (_windowFlexibility - 1)) _windowMax--;
      }
    }
    _fastRounds = 0;
  }

  RnsPacket _partRequest(List<int> indices) {
    final b = BytesBuilder()
      ..addByte(_hashmapNotExhausted)
      ..add(_resourceHash);
    for (final i in indices) {
      b.add(_mapHashes[i]!);
    }
    return link.encrypt(b.toBytes(), context: RnsContext.resourceReq);
  }

  /// RNS HMU request: [0xFF][last_map_hash(4)][resource_hash(32)]. The sender
  /// finds the part index of last_map_hash and replies with the next hashmap
  /// batch (RNS/Resource.request). last_map_hash = the highest contiguous hash
  /// we hold, which sits on a HASHMAP_MAX_LEN boundary.
  RnsPacket _hmuRequest() {
    final last = _mapHashes[_knownHashes - 1]!;
    final b = BytesBuilder()
      ..addByte(_hashmapExhausted)
      ..add(last)
      ..add(_resourceHash);
    return link.encrypt(b.toBytes(), context: RnsContext.resourceReq);
  }

  /// Ingest a RESOURCE_HMU (link-decrypted): resource_hash(32) +
  /// msgpack([hashmap_segment, hashmap_bytes]). Places the batch's hashes at
  /// segment*HASHMAP_MAX_LEN and advances the contiguous known count.
  void ingestHmu(Uint8List data) {
    if (data.length < _hashLen) return;
    if (!RnsCrypto.constantTimeEquals(
        Uint8List.sublistView(data, 0, _hashLen), _resourceHash)) {
      return; // for a different segment
    }
    final m = _MsgpackDecoder(Uint8List.sublistView(data, _hashLen)).decode();
    if (m is! List || m.length < 2) return;
    final segment = m[0];
    final hashmap = m[1];
    if (segment is! int || hashmap is! Uint8List) return;
    final base = segment * _reqBatch;
    final count = hashmap.length ~/ _mapHashLen;
    for (var k = 0; k < count; k++) {
      final idx = base + k;
      if (idx >= 0 && idx < _n && _mapHashes[idx] == null) {
        _setHash(idx, Uint8List.sublistView(hashmap, k * _mapHashLen, (k + 1) * _mapHashLen));
      }
    }
    while (_knownHashes < _n && _mapHashes[_knownHashes] != null) {
      _knownHashes++;
    }
    _hmuOutstanding = false;
  }

  /// Ingest one RESOURCE part (raw packet data; not per-part encrypted). Matches
  /// it to its index by map-hash. Returns true once the current SEGMENT is
  /// complete (then [segmentComplete] is set and [proofPacket] is available; if it
  /// was the last segment, [complete]/[payload] are set too).
  bool ingestPart(Uint8List part) {
    if (_segmentComplete || _complete) return _segmentComplete;
    final mapHash = _hex(Uint8List.sublistView(
        RnsCrypto.fullHash([...part, ..._mapRandom]), 0, _mapHashLen));
    final idx = _hashIndex[mapHash];
    if (idx == null || _parts.containsKey(idx)) return false; // unknown/dup
    _parts[idx] = Uint8List.fromList(part);
    _outstanding.remove(idx);
    // A full window arrived with nothing left in flight → grow the window (and
    // ramp _windowMax after a few clean rounds). Matches RNS receive_part().
    if (_outstanding.isEmpty && _parts.length < _n) _growWindow();
    if (_parts.length < _n) return false;
    return _finishSegment();
  }

  bool _finishSegment() {
    final encrypted = BytesBuilder();
    for (var i = 0; i < _n; i++) {
      final p = _parts[i];
      if (p == null) return false; // still missing one
      encrypted.add(p);
    }
    final enc = encrypted.toBytes();
    if (_transferSize > 0 && enc.length != _transferSize) {
      return _fail('encrypted size ${enc.length} != advertised $_transferSize');
    }
    Uint8List stream;
    try {
      stream = _encrypted ? link.tokenDecrypt(enc) : enc;
    } catch (e) {
      return _fail('stream decrypt failed: $e');
    }
    if (stream.length < _randomHashSize) {
      return _fail('stream shorter than random header');
    }
    final segData = Uint8List.sublistView(stream, _randomHashSize);
    // NOTE: the advertisement 'd' field is the resource's TOTAL data size (all
    // segments), NOT this segment's size — so it must NOT be compared against a
    // single segment (that rejects every multi-segment transfer from a correct
    // sender, e.g. reference RNS, where seg size < total). Per-segment integrity
    // is verified by the resource_hash; the total is checked once assembled.
    final check = Uint8List.sublistView(
        RnsCrypto.fullHash([...segData, ..._mapRandom]), 0, _hashLen);
    if (!RnsCrypto.constantTimeEquals(check, _resourceHash)) {
      return _fail('resource hash mismatch');
    }
    _assembled.add(segData);
    _pendingProof = RnsCrypto.fullHash([...segData, ..._resourceHash]);
    _segmentComplete = true;
    if (_segIndex + 1 >= _totalSegments) {
      final full = _assembled.toBytes();
      if (_dataSize > 0 && full.length != _dataSize) {
        return _fail('total size ${full.length} != advertised $_dataSize');
      }
      _payload = full;
      _complete = true;
    } else {
      // Non-final segment: surface its plaintext so the owner can persist it for
      // resume (the final segment is delivered whole via [payload] instead).
      _lastSegData = Uint8List.fromList(segData);
      _lastSegIndex = _segIndex;
    }
    return true;
  }

  /// The RESOURCE_PRF proof packet for the just-completed segment: data =
  /// resource_hash(32) + proof(32). Send it after [segmentComplete]; the sender
  /// validates it and advertises the next segment. Null if no segment is done.
  RnsPacket? proofPacket() {
    final proof = _pendingProof;
    if (!_segmentComplete || proof == null) return null;
    final data = BytesBuilder()
      ..add(_resourceHash)
      ..add(proof);
    // RNS sends resource proofs UNENCRYPTED as a PROOF-type packet addressed to
    // the link (RNS/Packet.py: for RESOURCE_PRF, ciphertext = data). Encrypting
    // it (or sending it as DATA) leaves the sender unable to validate it, so it
    // never advertises the next segment — multi-segment transfers stall.
    return RnsPacket(
      destHash: link.linkId!,
      data: data.toBytes(),
      headerType: RnsHeaderType.header1,
      destType: RnsDestType.link,
      packetType: RnsPacketType.proof,
      context: RnsContext.resourcePrf,
    );
  }

  bool _fail(String why) {
    _error = why;
    return false;
  }

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  static int _asInt(Object? v) => v is int ? v : 0;
  static Uint8List _asBin(Object? v) =>
      v is Uint8List ? v : (v is List<int> ? Uint8List.fromList(v) : Uint8List(0));
}

/// Minimal msgpack decoder for the resource advertisement: fixmap/map16,
/// fixstr/str8, positive/uint ints, bin8/bin16, nil. Mirrors the encoder in
/// rns_resource.dart (umsgpack subset).
class _MsgpackDecoder {
  final Uint8List _b;
  int _i = 0;
  _MsgpackDecoder(this._b);

  Object? decode() {
    final c = _b[_i++];
    if (c <= 0x7f) return c; // positive fixint
    if (c >= 0xe0) return c - 256; // negative fixint
    if ((c & 0xf0) == 0x80) return _map(c & 0x0f); // fixmap
    if ((c & 0xf0) == 0x90) return _array(c & 0x0f); // fixarray
    if ((c & 0xe0) == 0xa0) return _str(c & 0x1f); // fixstr
    switch (c) {
      case 0xc0:
        return null; // nil
      case 0xc2:
        return false;
      case 0xc3:
        return true;
      case 0xc4:
        return _bin(_b[_i++]); // bin8
      case 0xc5:
        final n = (_b[_i] << 8) | _b[_i + 1];
        _i += 2;
        return _bin(n); // bin16
      case 0xcc:
        return _b[_i++]; // uint8
      case 0xcd:
        final v = (_b[_i] << 8) | _b[_i + 1];
        _i += 2;
        return v; // uint16
      case 0xce:
        final v =
            (_b[_i] << 24) | (_b[_i + 1] << 16) | (_b[_i + 2] << 8) | _b[_i + 3];
        _i += 4;
        return v; // uint32
      case 0xd9:
        return _str(_b[_i++]); // str8
      case 0xde:
        final n = (_b[_i] << 8) | _b[_i + 1];
        _i += 2;
        return _map(n); // map16
      case 0xdc:
        final n = (_b[_i] << 8) | _b[_i + 1];
        _i += 2;
        return _array(n); // array16
      default:
        throw FormatException('unsupported msgpack byte 0x${c.toRadixString(16)}');
    }
  }

  Map<String, Object?> _map(int n) {
    final out = <String, Object?>{};
    for (var k = 0; k < n; k++) {
      final key = decode();
      final val = decode();
      out['$key'] = val;
    }
    return out;
  }

  List<Object?> _array(int n) => [for (var k = 0; k < n; k++) decode()];

  String _str(int n) {
    final s = String.fromCharCodes(_b.sublist(_i, _i + n));
    _i += n;
    return s;
  }

  Uint8List _bin(int n) {
    final out = Uint8List.sublistView(_b, _i, _i + n);
    _i += n;
    return Uint8List.fromList(out);
  }
}
