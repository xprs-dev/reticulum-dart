/*
 * A Reticulum client behind a gateway (portal/docs/plan-browser-reticulum.md):
 * one interface to the gateway, frames each way (a WebSocket), a leaf node
 * that learns paths from the gateway's answers, and request clients that
 * open links to stations through it. No dart:io: the browser build uses it
 * as it is, and so does a test or a tool on a computer.
 */
import 'dart:async';
import 'dart:typed_data';

import 'rns_frame_interface.dart';
import 'rns_identity.dart';
import 'rns_packet.dart';
import 'rns_request.dart';
import 'rns_transport.dart';

class RnsGatewayClient {
  RnsGatewayClient(void Function(Uint8List frame) sendFrame, {this.log})
      : iface = RnsFrameInterface('gateway', sendFrame, uplink: true),
        transport = RnsTransport(log: log) {
    transport.addInterface(iface);
  }

  final void Function(String msg)? log;
  final RnsTransport transport;
  final RnsFrameInterface iface;
  final List<RnsRequestClient> _clients = [];
  /// Log every packet (a test, a debugging session).
  bool debug = false;
  static String _hex(Uint8List b) =>
      b.take(8).map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  /// A frame from the gateway: a Reticulum packet.
  Future<void> onFrame(Uint8List raw) async {
    final p = RnsPacket.parse(raw);
    if (p == null) {
      log?.call('gateway: a frame that is not a packet (${raw.length}B)');
      return;
    }
    if (p.packetType == RnsPacketType.announce) {
      final a = await transport.ingest(p, iface.label);
      if (debug) log?.call('gateway: announce ${_hex(p.destHash)} ${a == null ? 'refused' : 'taken'}');
      return;
    }
    if (debug) log?.call('gateway: packet type ${p.packetType} to ${_hex(p.destHash)}');
    for (final c in List.of(_clients)) {
      if (await c.handlePacket(p)) return;
    }
  }

  /// A request client for [station]'s destination ([appName], [aspects]):
  /// its link goes through the gateway, the path asked for when not held.
  RnsRequestClient client(RnsIdentity station,
      {String appName = 'xprs', List<String> aspects = const ['wapp']}) {
    final c = RnsRequestClient(
      peer: station,
      appName: appName,
      aspects: aspects,
      send: iface.send,
      nextHopForDest: (h) => transport.pathFor(h)?.nextHop,
      hasPathForDest: transport.hasPath,
      requestPath: (h) => transport.requestPath(h, force: true),
      nextHopMtuForDest: transport.nextHopInterfaceHwMtu,
      log: log,
    );
    _clients.add(c);
    return c;
  }

  void drop(RnsRequestClient c) {
    c.close();
    _clients.remove(c);
  }
}
