/*
 * RNS LAN interface — broadcast DISCOVERY, UNICAST data.
 *
 * Same-network nodes find each other without a hub, then exchange DATA (links,
 * resources, DHT, LXMF) directly at LAN speed instead of routing through an
 * internet hub just because they also see it.
 *
 * Wi-Fi drops/rate-limits BROADCAST (power-save, airtime protection), often
 * asymmetrically per device — proven live: one phone's subnet broadcasts
 * reached the other but never vice-versa, while direct UNICAST worked flawlessly
 * both ways. So this interface uses the medium the way every real LAN app does:
 *   - OUR OWN announces and path requests broadcast (limited 255.255.255.255 +
 *     each subnet-directed x.y.z.255) — cheap periodic discovery beacons — and
 *     are also unicast to every known peer, since Wi-Fi delivers unicast where
 *     it drops broadcast.
 *   - A RELAYED announce (one a transport node re-airs for somebody else,
 *     HEADER_2) is unicast to known peers only, and dropped when there are
 *     none. It discovers nothing: it is addressed at peers who are already
 *     here. Broadcasting it was the LAN storm — on a phone promoted to a
 *     transport node, every announce from four public hubs went out on the
 *     subnet and came straight back, nineteen thousand times in forty
 *     minutes, each copy parsed twice and shipped across an isolate before
 *     being thrown away.
 *   - DATA is UNICAST to each known peer's address. Peers are learned from the
 *     SOURCE of ANY datagram — a broadcast announce OR an inbound unicast — so
 *     the lane BOOTSTRAPS even from one-way broadcast: A hears B's announce and
 *     unicasts to B; B learns A's address from that unicast's source and
 *     unicasts back. Only ONE broadcast direction needs to work for full
 *     bidirectional unicast.
 * With no known peer yet, data has nowhere to go and is dropped (the peer will
 * be learned from the next announce, then link retries succeed) — never
 * broadcast, so a busy node can't blast transit traffic across the subnet.
 * One raw RNS packet per UDP datagram.
 *
 * Our own frames never come back in. A broadcast returns to its sender, from
 * an address we know or, after a Wi-Fi change, a hotspot, a P2P group, an
 * access point that reflects, one we do not; so the filter is not the source
 * address alone but a ring of the frames we just sent. The decisions live in
 * pure functions ([planTx], [isRelayedAnnounce], [LanSentRing]) so they are
 * tested without a socket.
 */
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'rns_packet.dart';
import 'rns_transport.dart';

/// What [RnsLanInterface.send] does with one frame.
enum LanTx {
  /// Discovery: every broadcast address AND every known peer.
  broadcastAndUnicast,

  /// Known peers only.
  unicastOnly,

  /// Nobody to send it to.
  drop,
}

/// A bounded memory of the frames we sent, so the copy the network hands
/// back is recognised whatever address it comes from. FNV-1a over the bytes:
/// two frames we sent that collide in 64 bits within the ring's lifetime is
/// not a case worth a byte of state.
class LanSentRing {
  LanSentRing({this.size = 128}) : _ring = List<int>.filled(size, 0);
  final int size;
  final List<int> _ring;
  int _next = 0;
  int _count = 0;

  static int digest(Uint8List raw) {
    var h = 0xcbf29ce484222325;
    for (final b in raw) {
      h ^= b;
      h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF;
    }
    return h;
  }

  void remember(Uint8List raw) {
    _ring[_next] = digest(raw);
    _next = (_next + 1) % size;
    if (_count < size) _count++;
  }

  bool contains(Uint8List raw) {
    final d = digest(raw);
    for (var i = 0; i < _count; i++) {
      if (_ring[i] == d) return true;
    }
    return false;
  }
}

class RnsLanInterface implements RnsInterface {
  @override
  final String label;

  @override
  bool get announceOnly => false;
  @override
  bool get edge => false;
  // LAN Ethernet/Wi-Fi: same HW MTU the reference RNS uses for UDP (1064) so
  // links negotiated over the LAN carry ~2x the protocol SDU.
  @override
  int get hardwareMtu => 1064;
  // Fastest medium we have — beats hub TCP and BLE for co-located peers.
  @override
  int get speedRank => 3;
  @override
  bool get uplink => false;

  final int port; // shared listen + send port (all XPRS nodes use the same)
  final String broadcastHost;
  final void Function(Uint8List packetRaw) onPacket;
  final void Function(String msg)? log;

  RawDatagramSocket? _socket;
  late final InternetAddress _broadcastAddr;

  /// Our own IPv4 addresses, so our broadcast loopback (which we also receive)
  /// is never re-processed or learned as a peer. Re-learned periodically: the
  /// list at bind time is the list before Wi-Fi settled.
  final Set<String> _selfAddrs = {};
  int _selfLearnedMs = 0;
  static const int _selfRelearnMs = 60 * 1000;

  /// Subnet-directed broadcast addresses (x.y.z.255 for each local /24), sent
  /// in addition to the limited 255.255.255.255 — Wi-Fi setups differ in which
  /// they forward, so announces go to both to maximise discovery.
  final List<InternetAddress> _directedBcast = [];

  /// Peers learned from inbound datagram sources: ip -> (addr, port, lastMs).
  /// Data is unicast to these. Bounded; stale entries age out.
  final Map<String, _LanPeer> _peers = {};
  static const int _peerTtlMs = 10 * 60 * 1000;
  static const int _maxPeers = 32;

  final LanSentRing _sent = LanSentRing();

  /// Frames we sent that the network handed back, and were dropped unread.
  int get selfDropped => _selfDropped;
  int _selfDropped = 0;

  /// Relayed announces and data with nobody on the LAN to give them to.
  int get nobodyDropped => _nobodyDropped;
  int _nobodyDropped = 0;

  int get peerCount => _peers.length;

  RnsLanInterface({
    required this.port,
    required this.onPacket,
    this.broadcastHost = '255.255.255.255',
    this.log,
    String? label,
  }) : label = label ?? 'lan';

  // Cheap tests straight off the flags byte — no full parse.
  // flags = (header_type<<6)|(context_flag<<5)|(transport_type<<4)|
  //         (dest_type<<2)|packet_type
  static bool _isAnnounce(Uint8List raw) =>
      raw.isNotEmpty && (raw[0] & 0x03) == RnsPacketType.announce;

  /// An announce a transport node re-aired for somebody else: HEADER_2 carries
  /// the relayer's id. Our own announce, and a neighbour's own, are HEADER_1.
  static bool isRelayedAnnounce(Uint8List raw) =>
      _isAnnounce(raw) && ((raw[0] >> 6) & 0x03) == RnsHeaderType.header2;

  /// The send policy, as a pure function of the frame and how many peers we
  /// know. Discovery (our own announce, a path request) must work with nobody
  /// known yet; everything else has a recipient or has none.
  static LanTx planTx(Uint8List raw, {required int peers}) {
    if (isRelayedAnnounce(raw)) {
      return peers > 0 ? LanTx.unicastOnly : LanTx.drop;
    }
    if (_isAnnounce(raw) || RnsTransport.isPathRequest(raw)) {
      return LanTx.broadcastAndUnicast;
    }
    return peers > 0 ? LanTx.unicastOnly : LanTx.drop;
  }

  Future<void> bind() async {
    _broadcastAddr = InternetAddress(broadcastHost);
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
    s.broadcastEnabled = true;
    _socket = s;
    await _learnSelfAddresses();
    log?.call('LAN on UDP $port (broadcast discovery + unicast data)');
    s.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      final src = dg.address.address;
      final data = Uint8List.fromList(dg.data);
      if (_selfAddrs.contains(src) || _sent.contains(data)) {
        // Ours, coming back. Nothing here teaches us anything: our own
        // announce, our own rebroadcast of somebody else's. Dropping it
        // before onPacket is what saves the parse, the isolate hop and, for
        // a rebroadcast, learning a path to a peer through ourselves.
        _selfDropped++;
        return;
      }
      // Learn the peer off ANY datagram (announce OR unicast) so the data
      // lane bootstraps bidirectional unicast from one-way broadcast.
      _learnPeer(src, dg.address, dg.port);
      try {
        onPacket(data);
      } catch (e) {
        log?.call('onPacket error: $e');
      }
    });
  }

  Future<void> _learnSelfAddresses() async {
    _selfLearnedMs = _nowMs();
    try {
      final found = <String>{};
      final directed = <InternetAddress>[];
      for (final ni in await NetworkInterface.list(
          type: InternetAddressType.IPv4)) {
        for (final a in ni.addresses) {
          if (a.isLoopback) continue;
          found.add(a.address);
          final parts = a.address.split('.'); // assume /24 (home-LAN norm)
          if (parts.length == 4) {
            final d = '${parts[0]}.${parts[1]}.${parts[2]}.255';
            if (!directed.any((x) => x.address == d)) {
              directed.add(InternetAddress(d));
            }
          }
        }
      }
      // Addresses only accumulate: one we had a minute ago may still be the
      // source of a frame in flight, and a stale extra entry costs nothing.
      _selfAddrs.addAll(found);
      for (final d in directed) {
        if (!_directedBcast.any((x) => x.address == d.address)) {
          _directedBcast.add(d);
        }
      }
    } catch (_) {}
  }

  void _learnPeer(String ip, InternetAddress addr, int fromPort) {
    final known = _peers.containsKey(ip);
    _peers[ip] = _LanPeer(
        addr, fromPort == 0 ? port : fromPort, _nowMs());
    if (!known) log?.call('LAN peer $ip (${_peers.length} known)');
    if (_peers.length > _maxPeers) {
      String? oldest;
      var oldestMs = 1 << 62;
      for (final e in _peers.entries) {
        if (e.value.lastMs < oldestMs) {
          oldestMs = e.value.lastMs;
          oldest = e.key;
        }
      }
      if (oldest != null) _peers.remove(oldest);
    }
  }

  int _nowMs() => DateTime.now().millisecondsSinceEpoch;

  @override
  void send(Uint8List packetRaw) {
    final s = _socket;
    if (s == null) return;
    final now = _nowMs();
    _peers.removeWhere((_, p) => p.lastMs < now - _peerTtlMs);
    if (now - _selfLearnedMs > _selfRelearnMs) {
      unawaited(_learnSelfAddresses());
    }
    switch (planTx(packetRaw, peers: _peers.length)) {
      case LanTx.drop:
        _nobodyDropped++;
        return;
      case LanTx.broadcastAndUnicast:
        // Discovery: broadcast (limited + every subnet-directed address) AND
        // unicast to every known peer. Wi-Fi drops broadcast heavily, so
        // relying on it alone left the LAN PATH intermittent. Once ANY datagram
        // from a peer has been seen, every subsequent announce reaches it by
        // reliable unicast, so the LAN path stays up. The broadcast keeps
        // first-contact working; the unicast keeps it STABLE.
        _sent.remember(packetRaw);
        s.send(packetRaw, _broadcastAddr, port);
        for (final d in _directedBcast) {
          s.send(packetRaw, d, port);
        }
        for (final p in _peers.values) {
          s.send(packetRaw, p.addr, p.port);
        }
      case LanTx.unicastOnly:
        // Wi-Fi delivers unicast reliably where it drops broadcast; and a
        // relayed announce or a data packet has a recipient, not an audience.
        _sent.remember(packetRaw);
        for (final p in _peers.values) {
          s.send(packetRaw, p.addr, p.port);
        }
    }
  }

  Future<void> close() async {
    _socket?.close();
    _socket = null;
  }
}

class _LanPeer {
  final InternetAddress addr;
  final int port;
  final int lastMs;
  _LanPeer(this.addr, this.port, this.lastMs);
}
