/*
 * RNS over BLE — broadcast-first interface.
 *
 * A shared BLE advertising medium is, physically, a broadcast RNS interface:
 * one connectionless transmission is heard by every device in range, and RNS's
 * own addressing decides who acts on each packet. That makes group traffic
 * efficient — an announce, or a packet to a GROUP/PLAIN destination, is aired
 * ONCE and reaches all N members, instead of N separate point-to-point sends
 * (the limitation of GATT-only designs like torlando-tech/ble-reticulum).
 *
 * So an ANNOUNCE always goes on the broadcast medium. Everything addressed,
 * though, prefers a point-to-point link when the radio has one: an advert is
 * fire-and-forget on a duty-cycled medium — unacknowledged, unretransmitted,
 * heard only by a scanner that happens to be listening in the same window —
 * which measured out as about half the messages between two phones vanishing
 * without a trace. With no link, addressed packets still broadcast if they fit
 * and fall back to point-to-point when they are too large to advertise.
 *
 * Reassembly + selective-repeat (NACK)
 * reliability for the chunked broadcast live in the underlying radio (XPRS's
 * BleService); RNS provides confidentiality/auth on top, so the BLE transport
 * itself needs no pairing.
 *
 * The [RnsBleRadio] abstraction keeps this file free of Flutter/BLE imports so
 * the broadcast routing is unit-testable; the on-device binding to BleService
 * lives in lib/connections/bluetooth/ble_rns_radio.dart.
 */
import 'dart:typed_data';

import 'rns_packet.dart' show kRnsMtu;
import 'rns_transport.dart';

/// A packet radio with a connectionless broadcast medium (one transmission ->
/// all in-range receivers) and an optional point-to-point path for oversized
/// frames. Chunking/reassembly/retransmit are the radio's responsibility.
abstract class RnsBleRadio {
  /// Largest RNS packet that fits the connectionless broadcast path.
  int get broadcastCap;

  /// Air [frame] once on the broadcast medium; every device in range receives
  /// and reassembles it.
  void broadcast(Uint8List frame);

  /// True when a point-to-point link (e.g. an open GATT connection) is up and
  /// can carry traffic right now. Broadcast adverts are fire-and-forget on a
  /// duty-cycled medium; a link is acknowledged and flow-controlled, so when
  /// one exists it is the better route for anything addressed to that peer.
  bool get hasLink => false;

  /// Send [frame] point-to-point (e.g. GATT) when it exceeds [broadcastCap].
  /// Returns false if no point-to-point path is currently available.
  bool unicast(Uint8List frame);

  /// Register the handler for inbound (already-reassembled) frames.
  void onReceive(void Function(Uint8List frame) handler);
}

/// An [RnsInterface] that carries RNS over a broadcast-capable BLE radio.
class RnsBleInterface implements RnsInterface {
  @override
  bool get announceOnly => false;
  @override
  int get speedRank => 1; // BLE: slowest data medium
  /// What this radio can ACTUALLY carry in one frame.
  ///
  /// This used to claim the 500-byte protocol MTU, which is what `hardwareMtu`
  /// exists to correct: RNS sizes links and resources to the medium, and a
  /// medium that promises 500 while its controller allows ~296 makes the stack
  /// build packets the radio then refuses. Telling the truth here is what lets
  /// Reticulum do its own fragmenting (a Resource over a link) instead of the
  /// transport inventing one.
  @override
  int get hardwareMtu {
    final cap = radio.broadcastCap;
    return (cap > 0 && cap < kRnsMtu) ? cap : kRnsMtu;
  }

  final RnsBleRadio radio;
  @override
  final String label;
  // True when this BLE interface is the edge of an edge-bridge node (see
  // RnsTransport.edgeBridge): announces are propagated edge→core but the core
  // flood is never re-aired onto it.
  @override
  final bool edge;
  final void Function(Uint8List packetRaw) onPacket;
  final void Function(String msg)? log;

  int _broadcasts = 0;
  int _unicasts = 0;
  int _dropped = 0;

  int get broadcastCount => _broadcasts;
  int get unicastCount => _unicasts;
  int get droppedCount => _dropped;

  RnsBleInterface({
    required this.radio,
    required this.onPacket,
    this.label = 'ble',
    this.edge = false,
    this.log,
  }) {
    radio.onReceive((frame) {
      try {
        onPacket(frame);
      } catch (e) {
        log?.call('onPacket error: $e');
      }
    });
  }

  /// [RnsInterface] send: broadcast once if it fits (the efficient path for
  /// announces and group/PLAIN destinations), else fall back to point-to-point.
  @override
  void send(Uint8List packetRaw) {
    // An ANNOUNCE is one-to-many by nature — every device in range wants it,
    // including ones we hold no link to — so it always goes on the broadcast
    // medium. Packet type lives in the low two bits of the header byte
    // (0 data, 1 announce, 2 link request, 3 proof).
    // EVERYTHING prefers the link when there is one — announces included.
    //
    // A BLE advert is fire-and-forget on a half-duplex medium: the peer's
    // scanner has to be listening in the same instant, nothing is acknowledged,
    // and nothing is retransmitted. This device now transmits in a short window
    // once a minute (the radio cannot hear while it talks), which makes the
    // advert channel narrower still — and an announce that is not heard is a
    // device nobody can address.
    //
    // A link is acknowledged and flow-controlled, and a peer we hold a link to
    // is precisely the peer whose announce matters most. The beacon is what
    // gets us to the link; the link carries the rest.
    if (radio.hasLink && radio.unicast(packetRaw)) {
      _unicasts++;
      return;
    }
    if (packetRaw.length <= radio.broadcastCap) {
      radio.broadcast(packetRaw);
      _broadcasts++;
    } else if (radio.unicast(packetRaw)) {
      _unicasts++;
    } else {
      _dropped++;
      log?.call('dropped ${packetRaw.length}B packet: '
          'exceeds broadcast cap and no point-to-point path');
    }
  }
}
