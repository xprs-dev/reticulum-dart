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
 *   - ANNOUNCES broadcast (limited 255.255.255.255 + each subnet-directed
 *     x.y.z.255) — cheap periodic discovery beacons.
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
 */
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'rns_packet.dart';
import 'rns_transport.dart';

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

  final int port; // shared listen + send port (all XPRS nodes use the same)
  final String broadcastHost;
  final void Function(Uint8List packetRaw) onPacket;
  final void Function(String msg)? log;

  RawDatagramSocket? _socket;
  late final InternetAddress _broadcastAddr;

  /// Our own IPv4 addresses, so our broadcast loopback (which we also receive)
  /// is never re-processed or learned as a peer.
  final Set<String> _selfAddrs = {};

  /// Subnet-directed broadcast addresses (x.y.z.255 for each local /24), sent
  /// in addition to the limited 255.255.255.255 — Wi-Fi setups differ in which
  /// they forward, so announces go to both to maximise discovery.
  final List<InternetAddress> _directedBcast = [];

  /// Peers learned from inbound datagram sources: ip -> (addr, port, lastMs).
  /// Data is unicast to these. Bounded; stale entries age out.
  final Map<String, _LanPeer> _peers = {};
  static const int _peerTtlMs = 10 * 60 * 1000;
  static const int _maxPeers = 32;

  RnsLanInterface({
    required this.port,
    required this.onPacket,
    this.broadcastHost = '255.255.255.255',
    this.log,
    String? label,
  }) : label = label ?? 'lan';

  // Cheap announce test straight off the header (flags & 0x03) — no full parse.
  static bool _isAnnounce(Uint8List raw) =>
      raw.isNotEmpty && (raw[0] & 0x03) == RnsPacketType.announce;

  Future<void> bind() async {
    _broadcastAddr = InternetAddress(broadcastHost);
    final s = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
    s.broadcastEnabled = true;
    _socket = s;
    try {
      for (final ni in await NetworkInterface.list(
          type: InternetAddressType.IPv4)) {
        for (final a in ni.addresses) {
          if (a.isLoopback) continue;
          _selfAddrs.add(a.address);
          final parts = a.address.split('.'); // assume /24 (home-LAN norm)
          if (parts.length == 4) {
            final directed = '${parts[0]}.${parts[1]}.${parts[2]}.255';
            if (!_directedBcast.any((d) => d.address == directed)) {
              _directedBcast.add(InternetAddress(directed));
            }
          }
        }
      }
    } catch (_) {}
    log?.call('LAN on UDP $port (broadcast discovery + unicast data)');
    s.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = s.receive();
      if (dg == null) return;
      final src = dg.address.address;
      if (_selfAddrs.contains(src)) {
        // Our own broadcast loopback — never re-process data or learn self.
        if (!_isAnnounce(dg.data)) return;
      } else {
        // Learn the peer off ANY datagram (announce OR unicast) so the data
        // lane bootstraps bidirectional unicast from one-way broadcast.
        _learnPeer(src, dg.address, dg.port);
      }
      try {
        onPacket(Uint8List.fromList(dg.data));
      } catch (e) {
        log?.call('onPacket error: $e');
      }
    });
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
    final cutoff = _nowMs() - _peerTtlMs;
    _peers.removeWhere((_, p) => p.lastMs < cutoff);
    // Path requests ride the discovery lane: they exist precisely to reach a
    // peer we have NOT learned yet, so unicasting them to known peers only
    // (the data rule below) made them a no-op for first contact — and between
    // two Dart nodes nobody else answers them.
    if (_isAnnounce(packetRaw) || RnsTransport.isPathRequest(packetRaw)) {
      // Discovery: broadcast (limited + every subnet-directed address) AND
      // unicast to every known peer. Wi-Fi drops broadcast heavily, so relying
      // on it alone left the LAN PATH intermittent — a peer's announce (the only
      // thing that establishes its LAN path) frequently never arrived. Once ANY
      // datagram from a peer has been seen (a broadcast that DID get through, or
      // any inbound unicast data), that peer is learned and every subsequent
      // announce reaches it by reliable unicast, so the LAN path stays up. The
      // broadcast keeps first-contact working; the unicast keeps it STABLE.
      s.send(packetRaw, _broadcastAddr, port);
      for (final d in _directedBcast) {
        s.send(packetRaw, d, port);
      }
      for (final p in _peers.values) {
        s.send(packetRaw, p.addr, p.port);
      }
      return;
    }
    // Data: UNICAST to each fresh known peer — Wi-Fi delivers unicast reliably
    // where it drops broadcast. No peer yet → drop (the peer is learned from its
    // announce, then link retries land); never broadcast data.
    for (final p in _peers.values) {
      s.send(packetRaw, p.addr, p.port);
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
