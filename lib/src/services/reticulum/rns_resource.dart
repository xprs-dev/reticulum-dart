/*
 * RNS Resource — sender side (wire-compatible, RNS 1.3.5 — RNS/Resource.py).
 *
 * A Resource transfers an arbitrary-size payload over an established Link. Large
 * data is split into SEGMENTS (<= MAX_EFFICIENT_SIZE each); each segment is sent
 * as its own advertise → request → parts → proof exchange, the segments linked by
 * a shared original_hash and a (segment_index, total_segments) pair. Within a
 * segment the payload is token-encrypted once and split into [resourceSdu]-byte
 * PARTS, each addressed by a 4-byte map_hash = full_hash(part + map_random)[:4].
 * The advertisement carries only the first HASHMAP_MAX_LEN map-hashes; the rest
 * are delivered on demand via HashMap-Update (HMU) packets when the receiver
 * requests them (a RESOURCE_REQ whose first byte is HASHMAP_IS_EXHAUSTED, 0xFF).
 *
 * The receiver pulls parts under a flow-control window, verifies each segment
 * (full_hash(segment_data + map_random) == resource_hash) and proves it
 * (RESOURCE_PRF = full_hash(segment_data + resource_hash)); the sender validates
 * the proof and advertises the next segment. There is no payload-size cap.
 */
import 'dart:math' as math;
import 'dart:typed_data';

import 'rns_crypto.dart';
import 'rns_link.dart';
import 'rns_packet.dart';

const int _mapHashLen = 4;
const int _randomHashSize = 4;
const int _hashLen = 32; // Identity.HASHLENGTH/8
// Map-hashes per advertisement / HMU batch. FIXED at 74 — RNS computes
// ResourceAdvertisement.HASHMAP_MAX_LEN once from the DEFAULT MTU's Link.MDU
// (floor((431-134)/4)=74), NOT from the per-link negotiated MTU. Link MTU
// discovery scales the part SDU (bigger parts), but the hashmap batch stays 74,
// so both ends must agree on 74 regardless of the negotiated MTU.
const int _hashmapMaxLen = 74;
const int _hashmapExhausted = 0xFF; // request flag: "send me more hashmap"

/// Per-segment cap (RNS Resource.MAX_EFFICIENT_SIZE = 1 MB - 1). Bounds the
/// encrypted copy held in memory at any time to one segment.
const int kMaxEfficientSize = 1048575;

final math.Random _rng = math.Random.secure();

class RnsResourceSender {
  final RnsLink link;
  final Uint8List payload;

  late final int totalSegments;
  late final Uint8List _originalHash; // first segment's resource hash
  int _segIndex = 0; // 0-based current segment
  bool complete = false;

  // Current-segment state (rebuilt by _prepareSegment).
  late Uint8List _encrypted; // link-encrypted segment stream
  final List<Uint8List> _parts = [];
  final List<Uint8List> _mapHashes = [];
  late Uint8List _resourceHash; // 32B, over segment plaintext + map random
  late Uint8List _mapRandom; // 4B
  late Uint8List _expectedProof; // 32B

  // Collision-guard window (RNS/Resource): the receiver's lowest consecutive
  // height as we last inferred it from an HMU request. All map-hash lookups are
  // confined to [_rmch : _rmch+_collisionGuard] so a 4-byte map-hash collision
  // far from the receiver's position can't make us serve the wrong part / batch.
  static const int _windowMax = 75; // Resource.WINDOW_MAX
  // RNS COLLISION_GUARD_SIZE = 2*WINDOW_MAX + HASHMAP_MAX_LEN (both fixed) = 224.
  static const int _collisionGuard = 2 * _windowMax + _hashmapMaxLen;
  int _rmch = 0; // receiver_min_consecutive_height (reset per segment)

  RnsResourceSender(this.link, this.payload);

  int get parts => _parts.length;
  int get segmentIndex => _segIndex;

  /// Prepare the resource (segment 0). Never throws on size — large payloads are
  /// segmented and the hashmap is delivered incrementally via HMU.
  void prepare() {
    totalSegments =
        payload.isEmpty ? 1 : ((payload.length - 1) ~/ kMaxEfficientSize) + 1;
    _prepareSegment(0);
    _originalHash = _resourceHash;
  }

  /// Prepare the resource starting at [startSegment] (resumed download — the
  /// fetcher already holds segments 0..startSegment-1). Out-of-range starts fall
  /// back to a whole-file [prepare]. The advertised `original_hash` is this
  /// resume segment's own hash; it is per-session random and need not match the
  /// original transfer's (the fetcher adopts it for intra-session segment-linking
  /// only). [validateProof] then advances startSegment+1..end normally.
  void prepareFrom(int startSegment) {
    totalSegments =
        payload.isEmpty ? 1 : ((payload.length - 1) ~/ kMaxEfficientSize) + 1;
    if (startSegment <= 0 || startSegment >= totalSegments) {
      _prepareSegment(0);
      _originalHash = _resourceHash;
      return;
    }
    _prepareSegment(startSegment);
    _originalHash = _resourceHash;
  }

  void _prepareSegment(int idx) {
    _segIndex = idx;
    _rmch = 0; // each segment's hashmap is requested from the start
    final start = idx * kMaxEfficientSize;
    final len = math.min(kMaxEfficientSize, payload.length - start);
    final segData = Uint8List.sublistView(payload, start, start + len);
    final stream = Uint8List(_randomHashSize + len)
      ..setRange(0, _randomHashSize, _randomBytes(_randomHashSize))
      ..setRange(_randomHashSize, _randomHashSize + len, segData);
    _encrypted = link.tokenEncrypt(stream);
    _mapRandom = _randomBytes(_randomHashSize);
    // Resource hash and proof are over the PLAINTEXT segment data (RNS computes
    // them pre-encryption); only the parts/map_hashes use the encrypted blob.
    _resourceHash = RnsCrypto.fullHash([...segData, ..._mapRandom]);
    _expectedProof = RnsCrypto.fullHash([...segData, ..._resourceHash]);

    final sdu = link.resourceSdu;
    final n = _encrypted.isEmpty ? 0 : (_encrypted.length + sdu - 1) ~/ sdu;
    _parts.clear();
    _mapHashes.clear();
    for (var i = 0; i < n; i++) {
      final s = i * sdu;
      final e = math.min(s + sdu, _encrypted.length);
      final chunk = Uint8List.fromList(Uint8List.sublistView(_encrypted, s, e));
      _parts.add(chunk);
      _mapHashes.add(Uint8List.fromList(Uint8List.sublistView(
          RnsCrypto.fullHash([...chunk, ..._mapRandom]), 0, _mapHashLen)));
    }
  }

  /// The RESOURCE_ADV packet for the CURRENT segment (link-encrypted). Carries the
  /// first HASHMAP_MAX_LEN map-hashes; the rest are fetched via HMU.
  RnsPacket advertisementPacket() {
    final firstBatch = BytesBuilder();
    final count = math.min(_hashmapMaxLen, _mapHashes.length);
    for (var i = 0; i < count; i++) {
      firstBatch.add(_mapHashes[i]);
    }
    final adv = _MsgpackEncoder()
      ..mapHeader(11)
      ..str('t')..integer(_encrypted.length) // this segment's transfer size
      ..str('d')..integer(payload.length) // TOTAL data size (all segments), per RNS
      ..str('n')..integer(_parts.length) // parts in this segment
      ..str('h')..bin(_resourceHash) // segment resource hash
      ..str('r')..bin(_mapRandom) // map random
      ..str('o')..bin(_originalHash) // original (first-segment) hash
      ..str('i')..integer(_segIndex + 1) // segment index (1-based)
      ..str('l')..integer(totalSegments) // total segments
      ..str('q')..nil() // request id (unused)
      ..str('f')..integer(0x01) // flags: encrypted
      ..str('m')..bin(firstBatch.toBytes()); // first hashmap batch
    return link.encrypt(adv.bytes(), context: RnsContext.resourceAdv);
  }

  /// Handle an inbound RESOURCE_REQ (already link-decrypted). Either a part
  /// request ([0x00][resourceHash 32][mapHash 4]*) → the requested part packets,
  /// or an HMU request ([0xFF][resourceHash 32][fromIndex 4]) → a RESOURCE_HMU
  /// packet with the next hashmap batch.
  List<RnsPacket> handleRequest(Uint8List requestData) {
    if (requestData.isEmpty) return const [];
    final wantsMore = requestData[0] == _hashmapExhausted;
    final pad = wantsMore ? 1 + _mapHashLen : 1;
    if (requestData.length < pad + _hashLen) return const [];
    final out = <RnsPacket>[];

    // Serve the explicitly requested parts FIRST, using the current
    // receiver_min_consecutive_height (before HMU advances it). Matches the
    // ordering in RNS/Resource.request().
    out.addAll(_servePartRequests(requestData, pad + _hashLen));

    if (wantsMore) {
      // RNS HMU request: [0xFF][last_map_hash(4)][resource_hash(32)][reqs...].
      // Locate last_map_hash *within the collision-guard window* — never the
      // whole part list — so a far-away 4-byte map-hash collision can't make us
      // miscompute the segment and re-send an already-known batch (which froze
      // the receiver's hashmap_height). Then send the NEXT hashmap batch.
      // Mirrors RNS/Resource.request()'s wants_more_hashmap branch exactly.
      final lastMapHash =
          Uint8List.sublistView(requestData, 1, 1 + _mapHashLen);
      final searchEnd = math.min(_rmch + _collisionGuard, _mapHashes.length);
      var partIndex = _rmch;
      for (var i = _rmch; i < searchEnd; i++) {
        partIndex++;
        if (RnsCrypto.constantTimeEquals(_mapHashes[i], lastMapHash)) break;
      }
      _rmch = math.max(partIndex - 1 - _windowMax, 0);
      // last_map_hash must land on a batch boundary; if it doesn't, skip the
      // HMU this round (the receiver re-requests) rather than send a wrong batch.
      if (partIndex % _hashmapMaxLen == 0) {
        out.add(_hmuPacket(partIndex ~/ _hashmapMaxLen));
      }
    }
    return out;
  }

  /// Serve the part packets for every map-hash listed in [requestData] starting
  /// at [start] (4 bytes each). The search is confined to the collision-guard
  /// window `[_rmch : _rmch+COLLISION_GUARD_SIZE]` so a colliding map-hash
  /// elsewhere in the file can't cause us to serve the wrong part. Shared by the
  /// part-request and HMU-request paths (RNS/Resource.request search_scope).
  List<RnsPacket> _servePartRequests(Uint8List requestData, int start) {
    if (start >= requestData.length) return const [];
    final wanted = <Uint8List>[];
    for (var off = start; off + _mapHashLen <= requestData.length;
        off += _mapHashLen) {
      wanted.add(Uint8List.sublistView(requestData, off, off + _mapHashLen));
    }
    if (wanted.isEmpty) return const [];
    final out = <RnsPacket>[];
    final end = math.min(_rmch + _collisionGuard, _mapHashes.length);
    for (var i = _rmch; i < end; i++) {
      for (final want in wanted) {
        if (RnsCrypto.constantTimeEquals(_mapHashes[i], want)) {
          out.add(_partPacket(_parts[i]));
          break;
        }
      }
    }
    return out;
  }

  /// RNS HMU response (RNS/Resource.request): resource_hash(32) +
  /// msgpack([hashmap_segment, hashmap_bytes]) where the bytes are the map-hashes
  /// for parts [segment*HASHMAP_MAX_LEN : (segment+1)*HASHMAP_MAX_LEN].
  RnsPacket _hmuPacket(int segment) {
    final start = segment * _hashmapMaxLen;
    final end = math.min((segment + 1) * _hashmapMaxLen, _mapHashes.length);
    final hashmap = BytesBuilder();
    for (var i = start; i < end; i++) {
      hashmap.add(_mapHashes[i]);
    }
    final body = (_MsgpackEncoder()
          ..arrayHeader(2)
          ..integer(segment)
          ..bin(hashmap.toBytes()))
        .bytes();
    final b = BytesBuilder()
      ..add(_resourceHash)
      ..add(body);
    return link.encrypt(b.toBytes(), context: RnsContext.resourceHmu);
  }

  RnsPacket _partPacket(Uint8List part) => RnsPacket(
        destHash: link.linkId!,
        data: part,
        headerType: RnsHeaderType.header1,
        destType: RnsDestType.link,
        packetType: RnsPacketType.data,
        context: RnsContext.resource,
      );

  /// Validate a RESOURCE_PRF (raw data = resource_hash + proof) for the current
  /// segment. On success: advance to the next segment (so the caller should send
  /// [advertisementPacket] again) or set [complete] after the last one. Returns
  /// true if the proof was valid.
  bool validateProof(Uint8List proofData) {
    if (proofData.length != _hashLen * 2) return false;
    final proof = Uint8List.sublistView(proofData, _hashLen);
    if (!RnsCrypto.constantTimeEquals(proof, _expectedProof)) return false;
    if (_segIndex + 1 < totalSegments) {
      _prepareSegment(_segIndex + 1);
    } else {
      complete = true;
    }
    return true;
  }
}

Uint8List _randomBytes(int n) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = _rng.nextInt(256);
  }
  return out;
}

/// Minimal msgpack encoder for the resource advertisement (fixmap, fixstr keys,
/// positive ints, bin, nil) — RNS uses umsgpack which accepts these forms.
class _MsgpackEncoder {
  final BytesBuilder _b = BytesBuilder();

  void mapHeader(int n) {
    if (n <= 15) {
      _b.addByte(0x80 | n);
    } else {
      _b.addByte(0xde);
      _b.addByte((n >> 8) & 0xff);
      _b.addByte(n & 0xff);
    }
  }

  void arrayHeader(int n) {
    if (n <= 15) {
      _b.addByte(0x90 | n);
    } else {
      _b.addByte(0xdc);
      _b.addByte((n >> 8) & 0xff);
      _b.addByte(n & 0xff);
    }
  }

  void str(String s) {
    final bytes = s.codeUnits;
    if (bytes.length <= 31) {
      _b.addByte(0xa0 | bytes.length);
    } else {
      _b.addByte(0xd9);
      _b.addByte(bytes.length);
    }
    _b.add(bytes);
  }

  void integer(int v) {
    if (v >= 0 && v <= 0x7f) {
      _b.addByte(v);
    } else if (v <= 0xff) {
      _b.addByte(0xcc);
      _b.addByte(v);
    } else if (v <= 0xffff) {
      _b.addByte(0xcd);
      _b.addByte((v >> 8) & 0xff);
      _b.addByte(v & 0xff);
    } else {
      _b.addByte(0xce);
      _b.addByte((v >> 24) & 0xff);
      _b.addByte((v >> 16) & 0xff);
      _b.addByte((v >> 8) & 0xff);
      _b.addByte(v & 0xff);
    }
  }

  void bin(Uint8List data) {
    if (data.length <= 0xff) {
      _b.addByte(0xc4);
      _b.addByte(data.length);
    } else {
      _b.addByte(0xc5);
      _b.addByte((data.length >> 8) & 0xff);
      _b.addByte(data.length & 0xff);
    }
    _b.add(data);
  }

  void nil() => _b.addByte(0xc0);

  Uint8List bytes() => _b.toBytes();
}
