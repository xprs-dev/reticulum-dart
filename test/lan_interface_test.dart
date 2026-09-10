/*
 * The LAN interface's send and accept rules, as pure functions — no socket.
 * A relayed announce (HEADER_2, re-aired by a transport node) discovers
 * nothing, so it goes to known peers only and to nobody when there are none;
 * our own announce and a path request still broadcast, since discovery must
 * work with zero peers. And a frame we sent is recognised on the way back
 * whatever address it returns from.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:reticulum/src/services/reticulum/rns_lan_interface.dart';

Uint8List _frame({required int headerType, required int packetType}) {
  final flags = (headerType << 6) | packetType;
  final b = Uint8List(40)..[0] = flags;
  return b;
}

void main() {
  final ownAnnounce = _frame(
      headerType: RnsHeaderType.header1, packetType: RnsPacketType.announce);
  final relayedAnnounce = _frame(
      headerType: RnsHeaderType.header2, packetType: RnsPacketType.announce);
  final data = _frame(
      headerType: RnsHeaderType.header2, packetType: RnsPacketType.data);

  group('classification', () {
    test('a HEADER_2 announce is a relayed one; HEADER_1 is somebody\'s own', () {
      expect(RnsLanInterface.isRelayedAnnounce(relayedAnnounce), isTrue);
      expect(RnsLanInterface.isRelayedAnnounce(ownAnnounce), isFalse);
      expect(RnsLanInterface.isRelayedAnnounce(data), isFalse);
    });
  });

  group('send policy', () {
    test('our own announce broadcasts even with nobody known', () {
      expect(RnsLanInterface.planTx(ownAnnounce, peers: 0),
          LanTx.broadcastAndUnicast);
      expect(RnsLanInterface.planTx(ownAnnounce, peers: 3),
          LanTx.broadcastAndUnicast);
    });

    test('a relayed announce goes to known peers only, and to nobody when none',
        () {
      expect(RnsLanInterface.planTx(relayedAnnounce, peers: 2),
          LanTx.unicastOnly);
      expect(RnsLanInterface.planTx(relayedAnnounce, peers: 0), LanTx.drop,
          reason: 'this was the LAN storm: a promoted phone re-airing four '
              'hubs\' announces onto an empty subnet, and hearing them all back');
    });

    test('data is unicast, never broadcast', () {
      expect(RnsLanInterface.planTx(data, peers: 1), LanTx.unicastOnly);
      expect(RnsLanInterface.planTx(data, peers: 0), LanTx.drop);
    });
  });

  group('sent ring', () {
    test('a frame we sent is recognised on the way back', () {
      final ring = LanSentRing(size: 4);
      ring.remember(ownAnnounce);
      expect(ring.contains(Uint8List.fromList(ownAnnounce)), isTrue,
          reason: 'by content, not by identity of the buffer');
      expect(ring.contains(relayedAnnounce), isFalse);
    });

    test('the digest fits the web, where an int is a double', () {
      // The 64-bit FNV constants this used to carry (0xcbf29ce484222325) are
      // not representable in JavaScript, and dart2js refused the file: the
      // whole web build failed on them. Both lanes must therefore stay inside
      // 32 bits, on every platform, or the browser and the VM would disagree
      // about which frame is our own echo.
      final (hi, lo) = LanSentRing.digest(Uint8List.fromList([1, 2, 3, 250]));
      for (final v in [hi, lo]) {
        expect(v, greaterThanOrEqualTo(0));
        expect(v, lessThanOrEqualTo(0xFFFFFFFF));
      }
      expect(hi, isNot(lo), reason: 'two lanes, or it is 32 bits twice');
    });

    test('the digest depends on every byte and on their order', () {
      Uint8List b(List<int> v) => Uint8List.fromList(v);
      expect(LanSentRing.digest(b([1, 2, 3])),
          isNot(LanSentRing.digest(b([1, 2, 4]))));
      expect(LanSentRing.digest(b([1, 2, 3])),
          isNot(LanSentRing.digest(b([3, 2, 1]))));
      expect(LanSentRing.digest(b([1, 2, 3])),
          isNot(LanSentRing.digest(b([1, 2, 3, 0]))),
          reason: 'a trailing zero is a different frame');
      expect(LanSentRing.digest(b([1, 2, 3])), LanSentRing.digest(b([1, 2, 3])),
          reason: 'and the same bytes are the same frame');
    });

    test('the ring is bounded and forgets the oldest', () {
      final ring = LanSentRing(size: 2);
      final a = Uint8List.fromList([1, 2, 3]);
      final b = Uint8List.fromList([4, 5, 6]);
      final c = Uint8List.fromList([7, 8, 9]);
      ring
        ..remember(a)
        ..remember(b)
        ..remember(c);
      expect(ring.contains(a), isFalse);
      expect(ring.contains(b), isTrue);
      expect(ring.contains(c), isTrue);
    });
  });
}
