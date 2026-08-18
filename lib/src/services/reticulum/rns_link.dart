/*
 * RNS Link establishment (wire-compatible, RNS 1.3.5 — RNS/Link.py).
 *
 * The 3-packet handshake (initiator side, the path we drive):
 *   1. LINKREQUEST -> destination (SINGLE): data = eph_x25519_pub(32) +
 *      eph_ed25519_pub(32) + signalling(3). link_id = truncated_hash of the
 *      packet's hashable part with the 3 signalling bytes stripped.
 *   2. LRPROOF <- responder (dest LINK, context LRPROOF): data = signature(64) +
 *      responder_eph_x25519_pub(32) + signalling(3). The signature is by the
 *      DESTINATION identity's Ed25519 key over
 *      link_id + responder_pub + dest_ed_pub + signalling.
 *   3. LRRTT -> responder (encrypted DATA over the link, context LRRTT): payload
 *      = msgpack(rtt_float). This activates the link on the responder.
 *
 * Both sides derive shared = X25519(own_eph_prv, peer_eph_pub) and
 * key = HKDF(64, shared, salt=link_id, context=None); link traffic is a Token
 * (AES-256-CBC + HMAC) over that key. Mode pinned to AES_256_CBC (RNS default).
 */
import 'dart:math' as math;
import 'dart:typed_data';

import 'rns_crypto.dart';
import 'rns_identity.dart';
import 'rns_packet.dart';

const int kLinkModeAes256Cbc = 0x01; // RNS Link.MODE_DEFAULT
const int _ecPubHalf = 32; // X25519 pub
const int _sigLen = 64;
const int _linkMtuSize = 3;

enum RnsLinkStatus { pending, handshake, active, closed }

/// Initiator-side RNS link to a known destination identity.
class RnsLink {
  final RnsIdentity destinationIdentity;
  final Uint8List destHash;
  final int mode = kLinkModeAes256Cbc;
  // Negotiated via link MTU discovery: the initiator offers its next-hop
  // interface MTU, the responder caps + echoes it, both ends end up equal.
  // Default [kRnsMtu] (500) for peers/interfaces that don't do discovery.
  int mtu = kRnsMtu;

  // Our ephemeral keys for this link. The X25519 pair MUST be fresh per link —
  // it is the ECDH half, and reuse would destroy forward secrecy.
  late final Uint8List _xPrv;
  late final Uint8List _xPub;

  // The ephemeral Ed25519 PUBLIC key is only placed in the request/proof; its
  // private half is never used (it would only matter for the optional,
  // unimplemented link-identify step), so minting a fresh keypair per link was
  // a full Curve25519 scalar multiplication spent on a key we never sign with.
  // On a node answering a stream of inbound relay queries that was one of the
  // hottest things the CPU did. Share one rotating pair instead: rotated
  // periodically so it stays a short-lived value rather than a permanent
  // cross-link identifier, at ~zero cost.
  late final Uint8List _edPub;

  static Uint8List? _sharedEdPub;
  static int _sharedEdPubAt = 0;
  static const int _sharedEdPubTtlMs = 10 * 60 * 1000;

  static Future<Uint8List> _ephemeralEdPub() async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final cached = _sharedEdPub;
    if (cached != null && now - _sharedEdPubAt < _sharedEdPubTtlMs) {
      return cached;
    }
    final e = await RnsCrypto.ed25519Generate();
    _sharedEdPub = e.pub;
    _sharedEdPubAt = now;
    return e.pub;
  }

  Uint8List? linkId;
  Uint8List? _derivedKey;
  RnsToken? _token;
  RnsLinkStatus status = RnsLinkStatus.pending;
  double rtt = 0;

  /// Next-hop transport id (16B) when the peer is reachable THROUGH a transport
  /// node (rnsd). When set, outbound packets are HEADER_2 with transport_type=
  /// TRANSPORT and this transport_id, so the transport forwards them. Null = the
  /// peer is a direct neighbour (single-hop, HEADER_1).
  Uint8List? nextHop;

  // Responder-only: the peer's ephemeral X25519 public key (from the request),
  // and our own identity (with private keys) used to SIGN the proof.
  Uint8List? _peerXPub;
  RnsIdentity? _localIdentity;
  bool get isResponder => _localIdentity != null;

  RnsLink._(this.destinationIdentity, this.destHash);

  /// Create a RESPONDER link from an inbound LINKREQUEST addressed to one of our
  /// destinations. [localIdentity] is OUR identity (must hold private keys, to
  /// sign the proof). [request] is the parsed LINKREQUEST packet. Computes the
  /// same link_id the initiator did, generates our ephemeral X25519, and derives
  /// the shared session key. Call [buildProof] to get the LRPROOF to send back;
  /// the link becomes active when the initiator's LRRTT arrives ([handleRtt]).
  static Future<RnsLink> responder(
    RnsIdentity localIdentity,
    RnsPacket request, {
    int arrivalHwMtu = kRnsMtu,
  }) async {
    // request.data = peer_eph_x25519_pub(32) + peer_eph_ed25519_pub(32) +
    // signalling(3). We only need the peer X25519 pub to derive the key.
    final data = request.data;
    if (data.length < 2 * _ecPubHalf) {
      throw StateError('LINKREQUEST too short (${data.length})');
    }
    final peerXPub = Uint8List.sublistView(data, 0, _ecPubHalf);
    // destHash here is OUR destination hash (the request targets us).
    final link = RnsLink._(localIdentity, request.destHash);
    link._localIdentity = localIdentity;
    link._peerXPub = Uint8List.fromList(peerXPub);
    link.linkId = _linkIdFromRequest(request);
    // Link MTU discovery: if the request carries the 3 signalling bytes, the
    // initiator offered a link MTU. Cap it by what OUR return interface (the one
    // the request arrived on) can carry, then echo the result in the proof
    // (buildProof signals link.mtu). Both ends converge on this value.
    if (data.length >= 2 * _ecPubHalf + _linkMtuSize) {
      const off = 2 * _ecPubHalf;
      final offered =
          ((data[off] << 16) | (data[off + 1] << 8) | data[off + 2]) & 0x1FFFFF;
      link.mtu = _negotiatedMtu(offered, arrivalHwMtu);
    }
    final x = await RnsCrypto.x25519Generate();
    link._xPrv = x.priv;
    link._xPub = x.pub;
    link._edPub = await _ephemeralEdPub();
    final shared = await RnsCrypto.x25519Shared(x.priv, link._peerXPub!);
    link._derivedKey = RnsCrypto.hkdf(64, shared, salt: link.linkId, context: null);
    link._token = RnsToken(link._derivedKey!);
    link.status = RnsLinkStatus.handshake;
    return link;
  }

  /// Build the LRPROOF packet to send back to the initiator (responder side).
  /// Signs link_id + our_eph_x25519_pub + our_dest_ed25519_pub + signalling with
  /// our identity's Ed25519 key, matching what the initiator validates.
  Future<RnsPacket> buildProof() async {
    final id = _localIdentity;
    if (id == null) throw StateError('buildProof is responder-only');
    final signalling = signallingBytes(mtu, mode);
    final ourEdPub =
        Uint8List.sublistView(id.getPublicKey(), _ecPubHalf, 2 * _ecPubHalf);
    final signedData = BytesBuilder()
      ..add(linkId!)
      ..add(_xPub)
      ..add(ourEdPub)
      ..add(signalling);
    final sig = await id.sign(signedData.toBytes());
    final data = BytesBuilder()
      ..add(sig)
      ..add(_xPub)
      ..add(signalling);
    return RnsPacket(
      destHash: linkId!,
      data: data.toBytes(),
      headerType: RnsHeaderType.header1,
      transportType: RnsTransportType.broadcast,
      destType: RnsDestType.link,
      packetType: RnsPacketType.proof,
      context: RnsContext.lrproof,
    );
  }

  /// Responder: handle the initiator's LRRTT (encrypted DATA, context LRRTT)
  /// which activates the link. Returns true once active.
  bool handleRtt(RnsPacket p) {
    if (!isResponder || _token == null) return false;
    if (p.context != RnsContext.lrrtt) return false;
    try {
      _token!.decrypt(p.data); // msgpack(rtt); value not needed for the gate
    } catch (_) {
      return false;
    }
    status = RnsLinkStatus.active;
    return true;
  }

  /// Create an initiator link toward [destinationIdentity] (learned via an
  /// announce). [appName]/[aspects] name the destination (to compute its hash).
  static Future<RnsLink> initiator(
    RnsIdentity destinationIdentity,
    String appName,
    List<String> aspects,
  ) async {
    final destHash = RnsDestination.hash(destinationIdentity, appName, aspects);
    final link = RnsLink._(destinationIdentity, destHash);
    final x = await RnsCrypto.x25519Generate();
    link._xPrv = x.priv;
    link._xPub = x.pub;
    link._edPub = await _ephemeralEdPub();
    return link;
  }

  /// Resolve the next hop to [peer]'s (app, aspects) destination, pulling a path
  /// first if we don't have one. We may know a peer's IDENTITY (e.g. a DHT
  /// contact, or a relay learned out-of-band) without a cached path, because its
  /// announce was never flooded to us on busy/asymmetric public hubs; a
  /// PATH_REQUEST is a PULL the peer's attached hub answers on our direct link.
  /// Returns the hop (may still be null if the peer is genuinely unreachable).
  ///
  /// This is the single source of truth for the request-then-poll pattern that
  /// FileTransferNode and RelayNode both need before opening an initiator link.
  /// (LxmfRouter interleaves its own variant with message resolution and is left
  /// as-is to avoid destabilizing the working message path.)
  ///
  /// Reticulum routes PER-DESTINATION, not per-identity: the same node's `files`
  /// and `chat` destinations can be reached through DIFFERENT transport nodes
  /// (different hubs heard their announces). Prefer [hasPathForDest]/
  /// [nextHopForDest] (keyed by the SPECIFIC destination hash) so the link request
  /// is transport-addressed to the hub that actually has a route to THIS
  /// destination. The per-identity [nextHopFor] is a legacy fallback that picks
  /// any of the identity's paths — wrong when destinations route via different
  /// hubs, which silently broke link establishment to a different-hub peer.
  static Future<Uint8List?> ensurePath(
    RnsIdentity peer,
    String appName,
    List<String> aspects, {
    Uint8List? Function(RnsIdentity peer)? nextHopFor,
    Uint8List? Function(Uint8List destHash)? nextHopForDest,
    bool Function(Uint8List destHash)? hasPathForDest,
    void Function(Uint8List destHash)? requestPath,
    Duration pollInterval = const Duration(milliseconds: 300),
    int maxPolls = 10,
  }) async {
    final destHash = RnsDestination.hash(peer, appName, aspects);
    if (nextHopForDest != null) {
      // Per-destination routing (correct).
      var have = hasPathForDest?.call(destHash) ?? false;
      if (!have && requestPath != null) {
        requestPath(destHash);
        for (var i = 0; i < maxPolls && !have; i++) {
          await Future<void>.delayed(pollInterval);
          have = hasPathForDest?.call(destHash) ?? false;
        }
      }
      return nextHopForDest(destHash); // null = direct neighbour (HEADER_1)
    }
    // Legacy per-identity fallback.
    var hop = nextHopFor?.call(peer);
    if (hop == null && requestPath != null) {
      requestPath(destHash);
      for (var i = 0; i < maxPolls && hop == null; i++) {
        await Future<void>.delayed(pollInterval);
        hop = nextHopFor?.call(peer);
      }
    }
    return hop;
  }

  /// Open an initiator link to [destinationIdentity]'s (app, aspects) destination
  /// AND set its [nextHop] via [ensurePath] (pulling a path if needed) — the
  /// routable equivalent of [initiator]. Call [buildRequest] on the result.
  static Future<RnsLink> initiatorWithPath(
    RnsIdentity destinationIdentity,
    String appName,
    List<String> aspects, {
    Uint8List? Function(RnsIdentity peer)? nextHopFor,
    Uint8List? Function(Uint8List destHash)? nextHopForDest,
    bool Function(Uint8List destHash)? hasPathForDest,
    void Function(Uint8List destHash)? requestPath,
    int Function(Uint8List destHash)? nextHopMtuForDest,
    Duration pollInterval = const Duration(milliseconds: 300),
    int maxPolls = 10,
  }) async {
    final link = await initiator(destinationIdentity, appName, aspects);
    link.nextHop = await ensurePath(
      destinationIdentity,
      appName,
      aspects,
      nextHopFor: nextHopFor,
      nextHopForDest: nextHopForDest,
      hasPathForDest: hasPathForDest,
      requestPath: requestPath,
      pollInterval: pollInterval,
      maxPolls: maxPolls,
    );
    // Link MTU discovery: offer the next-hop interface's HW MTU (now that the
    // path is resolved) so [buildRequest] signals a larger link MTU on TCP.
    link.offerMtu(nextHopMtuForDest?.call(link.destHash) ?? kRnsMtu);
    return link;
  }

  /// Build the LINKREQUEST packet (sets [linkId]). Send its pack() on the wire.
  RnsPacket buildRequest() {
    final signalling = signallingBytes(mtu, mode);
    final data = BytesBuilder()
      ..add(_xPub)
      ..add(_edPub)
      ..add(signalling);
    final transported = nextHop != null;
    final pkt = RnsPacket(
      destHash: destHash,
      data: data.toBytes(),
      headerType:
          transported ? RnsHeaderType.header2 : RnsHeaderType.header1,
      transportType: transported
          ? RnsTransportType.transport
          : RnsTransportType.broadcast,
      destType: RnsDestType.single,
      packetType: RnsPacketType.linkRequest,
      transportId: transported ? nextHop : null,
      context: RnsContext.none,
    );
    linkId = _linkIdFromRequest(pkt);
    return pkt;
  }

  /// Handle the inbound LRPROOF. Validates the responder's signature, derives the
  /// session key, and returns the LRRTT packet to send (or null on failure).
  Future<RnsPacket?> handleProof(RnsPacket proof) async {
    if (status != RnsLinkStatus.pending) return null;
    if (proof.packetType != RnsPacketType.proof ||
        proof.context != RnsContext.lrproof) {
      return null;
    }
    final data = proof.data;
    // data = signature(64) + responder_pub(32) [+ signalling(3)]
    if (data.length != _sigLen + _ecPubHalf + _linkMtuSize &&
        data.length != _sigLen + _ecPubHalf) {
      return null;
    }
    final hasSignalling = data.length == _sigLen + _ecPubHalf + _linkMtuSize;
    final signature = Uint8List.sublistView(data, 0, _sigLen);
    final peerPub =
        Uint8List.sublistView(data, _sigLen, _sigLen + _ecPubHalf);
    var confirmedMtu = kRnsMtu;
    Uint8List signalling;
    if (hasSignalling) {
      final sb = Uint8List.sublistView(
          data, _sigLen + _ecPubHalf, _sigLen + _ecPubHalf + _linkMtuSize);
      confirmedMtu = ((sb[0] << 16) | (sb[1] << 8) | sb[2]) & 0x1FFFFF;
      signalling = signallingBytes(confirmedMtu, mode);
    } else {
      signalling = Uint8List(0);
    }

    // signed_data = link_id + peer_pub + dest_identity_ed_pub + signalling
    final destEdPub = Uint8List.sublistView(
        destinationIdentity.getPublicKey(), _ecPubHalf, 2 * _ecPubHalf);
    final signedData = BytesBuilder()
      ..add(linkId!)
      ..add(peerPub)
      ..add(destEdPub)
      ..add(signalling);
    final ok = await destinationIdentity.validate(
        Uint8List.fromList(signature), signedData.toBytes());
    if (!ok) return null;

    // Adopt the MTU the responder confirmed (was parsed-then-discarded before).
    // Without signalling this stays at the 500 default. Clamp for safety.
    mtu = _negotiatedMtu(confirmedMtu, kRnsLinkMtuMax);

    // Derive the session key.
    final shared = await RnsCrypto.x25519Shared(_xPrv, Uint8List.fromList(peerPub));
    _derivedKey = RnsCrypto.hkdf(64, shared, salt: linkId, context: null);
    _token = RnsToken(_derivedKey!);
    status = RnsLinkStatus.handshake;

    // LRRTT: encrypted DATA over the link carrying msgpack(rtt). A small nonzero
    // rtt is fine for the gate.
    rtt = 0.1;
    final rttPacket = encrypt(_msgpackFloat(rtt), context: RnsContext.lrrtt);
    status = RnsLinkStatus.active;
    return rttPacket;
  }

  /// Build an encrypted DATA packet over the link.
  ///
  /// Link DATA (LRRTT and all subsequent traffic) is ALWAYS addressed to the
  /// link_id as a plain HEADER_1 / destType=LINK packet — never transport-
  /// addressed, even when the peer is reachable through a transport node. A
  /// transport forwards link traffic by looking the link_id up in its LINK table
  /// (populated when it relayed the LINKREQUEST), not via the destination path
  /// table. Sending link DATA as HEADER_2 + transport_id makes the transport try
  /// a path lookup for the link_id, find none, and drop the packet (verified
  /// against rnsd: "no known path to final destination [link_id]"). Only
  /// [buildRequest] uses [nextHop] transport addressing, to reach the peer's
  /// destination in the first place.
  RnsPacket encrypt(Uint8List plaintext, {int context = RnsContext.none}) {
    if (_token == null) throw StateError('Link not established');
    return RnsPacket(
      destHash: linkId!,
      data: _token!.encrypt(plaintext),
      headerType: RnsHeaderType.header1,
      transportType: RnsTransportType.broadcast,
      destType: RnsDestType.link,
      packetType: RnsPacketType.data,
      context: context,
    );
  }

  /// Decrypt an inbound DATA packet addressed to this link.
  Uint8List decrypt(RnsPacket p) {
    if (_token == null) throw StateError('Link not established');
    return _token!.decrypt(p.data);
  }

  /// Raw link-token encrypt/decrypt (used by the Resource layer, which encrypts
  /// the whole stream once and ships the parts unencrypted).
  Uint8List tokenEncrypt(Uint8List plaintext) {
    if (_token == null) throw StateError('Link not established');
    return _token!.encrypt(plaintext);
  }

  Uint8List tokenDecrypt(Uint8List ciphertext) {
    if (_token == null) throw StateError('Link not established');
    return _token!.decrypt(ciphertext);
  }

  /// Resource SDU = mtu - HEADER_MAXSIZE(35) - IFAC_MIN_SIZE(1). For MTU 500
  /// this is 464 bytes per resource part (RNS Resource.__init__). Scales with
  /// the negotiated [mtu].
  int get resourceSdu => mtu - 35 - 1;

  // NOTE: the Resource hashmap batch length (RNS HASHMAP_MAX_LEN = 74) is a
  // FIXED constant derived from the DEFAULT MTU, not the negotiated link MTU —
  // see _hashmapMaxLen in rns_resource.dart. Only [resourceSdu] scales with MTU.

  /// Resolve a negotiated link MTU: the smaller of what was offered and what our
  /// side can carry ([ourCap], the return/next-hop interface HW MTU), bounded by
  /// the discovery ceiling and never below the 500-byte protocol MTU floor.
  static int _negotiatedMtu(int offered, int ourCap) {
    final m = math.min(offered, math.min(ourCap, kRnsLinkMtuMax));
    return m < kRnsMtu ? kRnsMtu : m;
  }

  /// Initiator: set the link MTU to OFFER in the request (= the next-hop
  /// interface HW MTU, capped at the ceiling, floored at the protocol MTU). Call
  /// before [buildRequest]; the responder caps it again and echoes the result.
  void offerMtu(int nextHopHwMtu) => mtu = _negotiatedMtu(nextHopHwMtu, kRnsLinkMtuMax);

  /// Is this packet addressed to this link (dest LINK, hash == link_id)?
  bool ownsPacket(RnsPacket p) =>
      p.destType == RnsDestType.link &&
      linkId != null &&
      RnsCrypto.constantTimeEquals(p.destHash, linkId!);

  /// Public: compute the link_id of a LINKREQUEST packet (used by a transport
  /// node to track and forward the link). Matches both HEADER_1 and HEADER_2.
  static Uint8List linkIdFromRequest(RnsPacket lr) => _linkIdFromRequest(lr);

  // link_id = truncated_hash(get_hashable_part - signalling). For HEADER_1,
  // hashable_part = [raw[0] & 0x0F] + raw[2:]; strip the trailing 3 signalling
  // bytes (data length exceeds ECPUBSIZE=64).
  static Uint8List _linkIdFromRequest(RnsPacket lr) {
    final raw = lr.pack();
    // get_hashable_part: low nibble of flags + everything from the dest_hash on
    // (skipping the 16B transport_id on HEADER_2). This makes the link_id match
    // whether the request is the initiator's HEADER_2 (transported) form or the
    // HEADER_1 form a transport delivers to the responder.
    final bodyStart = lr.headerType == RnsHeaderType.header2 ? 18 : 2;
    final hashable = BytesBuilder()
      ..addByte(raw[0] & 0x0F)
      ..add(Uint8List.sublistView(raw, bodyStart));
    var bytes = hashable.toBytes();
    const ecPubSize = 64;
    if (lr.data.length > ecPubSize) {
      final diff = lr.data.length - ecPubSize;
      bytes = Uint8List.sublistView(bytes, 0, bytes.length - diff);
    }
    return RnsCrypto.truncatedHash(bytes);
  }
}

/// RNS signalling bytes: 3 bytes packing the link MTU (low 21 bits) and the mode
/// (top 3 bits of the high byte). = struct.pack(">I", value)[1:].
Uint8List signallingBytes(int mtu, int mode) {
  final value = (mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16);
  return Uint8List.fromList([
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ]);
}

/// Minimal msgpack encoding of a single float (float64): 0xCB + 8 BE IEEE-754.
Uint8List _msgpackFloat(double v) {
  final out = Uint8List(9);
  out[0] = 0xCB;
  final bd = ByteData.sublistView(out, 1, 9);
  bd.setFloat64(0, v, Endian.big);
  return out;
}
