/*
 * A Reticulum interface over any transport that carries whole messages: one
 * Reticulum packet per frame, no HDLC (a WebSocket binary message). No
 * dart:io here, so the same class serves the gateway's side (a server's
 * WebSocket) and the browser's (a page's WebSocket).
 */
import 'dart:typed_data';

import 'rns_packet.dart' show kRnsLinkMtuMax;
import 'rns_transport.dart';

class RnsFrameInterface implements RnsInterface {
  RnsFrameInterface(this.label, this._send,
      {this.quiet = false, this.uplink = false, this.speedRank = 2});

  @override
  final String label;
  final void Function(Uint8List frame) _send;
  @override
  final bool quiet;
  @override
  final bool uplink;
  @override
  final int speedRank;
  @override
  bool get announceOnly => false;
  @override
  bool get edge => false;
  // A frame carries a packet of any size: links may negotiate a larger MTU.
  @override
  int get hardwareMtu => kRnsLinkMtuMax;

  int framesOut = 0;

  @override
  void send(Uint8List packetRaw) {
    framesOut++;
    try {
      _send(packetRaw);
    } catch (_) {}
  }
}
