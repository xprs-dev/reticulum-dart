/*
 * RNS Resource protocol round-trip tests — the regression lock for arbitrary-size
 * transfers. Establishes a real Link (handshake) between two endpoints, then
 * drives RnsResourceSender ↔ RnsResourceReceiver directly, routing every packet
 * between them, exercising multi-segment splitting, HashMap-Update (HMU) and the
 * windowed part requests. The headline cases (55 MB, 107 MB) prove there is no
 * size cap: the old implementation threw at >74 parts (~34 KB).
 */
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

/// Bring up an active Link pair (initiator + responder) sharing a session token.
/// [hwMtu] simulates the next-hop/arrival interface hardware MTU so the pair
/// runs link MTU discovery (both ends end up at the negotiated MTU).
Future<(RnsLink initiator, RnsLink responder)> _linkPair(
    {int hwMtu = kRnsMtu}) async {
  final dest = await RnsIdentity.generate(); // the responder's identity
  final initiator = await RnsLink.initiator(
      RnsIdentity.fromPublicKey(dest.getPublicKey()), 'test', ['resource']);
  initiator.offerMtu(hwMtu); // initiator offers its next-hop interface MTU
  final request = initiator.buildRequest();
  final responder =
      await RnsLink.responder(dest, request, arrivalHwMtu: hwMtu);
  final proof = await responder.buildProof();
  final rtt = await initiator.handleProof(proof);
  expect(rtt, isNotNull, reason: 'link handshake failed');
  responder.handleRtt(rtt!);
  return (initiator, responder);
}

Uint8List _bytes(int n, {int seed = 1}) {
  final out = Uint8List(n);
  var x = (seed * 2654435761) & 0xffffffff;
  for (var i = 0; i < n; i++) {
    x = (1103515245 * x + 12345) & 0x7fffffff;
    out[i] = (x >> 16) & 0xff;
  }
  return out;
}

Uint8List _sha(Uint8List b) =>
    Uint8List.fromList(crypto.sha256.convert(b).bytes);

/// Drive a full Resource transfer of [payload] over a fresh link pair. Optional
/// [corruptIndexEveryTime] flips a byte in every delivery of one part index (to
/// test integrity); [maxRounds] bounds the packet pump. Returns the received
/// payload, or null if it never completed.
Future<Uint8List?> _runTransfer(
  Uint8List payload, {
  int? corruptIndexEveryTime,
  int maxRounds = 80000000,
  int hwMtu = kRnsMtu,
}) async {
  final (initiator, responder) = await _linkPair(hwMtu: hwMtu);
  final sender = RnsResourceSender(responder, payload)..prepare();
  final rx = RnsResourceReceiver(initiator);

  // Packet queues: toRx = sender→receiver (adv/part/hmu); toTx = receiver→sender
  // (part/HMU requests, segment proofs).
  final toRx = <RnsPacket>[sender.advertisementPacket()];
  final toTx = <RnsPacket>[];
  var partCounter = 0;

  var rounds = 0;
  while ((toRx.isNotEmpty || toTx.isNotEmpty) && rounds++ < maxRounds) {
    while (toRx.isNotEmpty) {
      var p = toRx.removeAt(0);
      // Optional in-transit corruption of one specific part index, every time.
      if (corruptIndexEveryTime != null && p.context == RnsContext.resource) {
        if (partCounter == corruptIndexEveryTime) {
          final d = Uint8List.fromList(p.data)..[0] ^= 0xff;
          p = RnsPacket(
            destHash: p.destHash,
            data: d,
            headerType: RnsHeaderType.header1,
            destType: RnsDestType.link,
            packetType: RnsPacketType.data,
            context: RnsContext.resource,
          );
        }
        partCounter++;
      }
      toTx.addAll(rx.handle(p));
      if (rx.complete) return rx.payload;
      if (rx.error != null) return null;
    }
    while (toTx.isNotEmpty) {
      final p = toTx.removeAt(0);
      if (p.context == RnsContext.resourceReq) {
        toRx.addAll(sender.handleRequest(responder.decrypt(p)));
      } else if (p.context == RnsContext.resourcePrf) {
        // RNS resource proofs are UNENCRYPTED — validate raw p.data.
        if (sender.validateProof(p.data) && !sender.complete) {
          toRx.add(sender.advertisementPacket()); // next segment
        }
      }
    }
    // If nothing is queued but we're not done, nudge the receiver (covers a
    // window that drained exactly on a segment boundary).
    if (toRx.isEmpty && toTx.isEmpty && !rx.complete) {
      toTx.addAll(rx.pump());
      if (toTx.isEmpty) break; // genuinely stuck
    }
  }
  return rx.complete ? rx.payload : null;
}

void main() {
  group('RNS Resource transfer (multi-segment + HMU + window)', () {
    for (final spec in const [
      ('1 MB', 1024 * 1024),
      ('16 MB', 16 * 1024 * 1024),
      ('55 MB', 55 * 1024 * 1024),
      ('107 MB', 107 * 1024 * 1024), // was impossible (>74 parts threw)
    ]) {
      test('round-trips ${spec.$1} byte-exact', () async {
        final payload = _bytes(spec.$2, seed: spec.$2);
        final got = await _runTransfer(payload);
        expect(got, isNotNull, reason: '${spec.$1} did not complete');
        expect(got!.length, payload.length);
        expect(_sha(got), equals(_sha(payload)), reason: 'bytes differ');
      }, timeout: const Timeout(Duration(minutes: 5)));
    }

    test('round-trips an empty payload', () async {
      final got = await _runTransfer(Uint8List(0));
      expect(got, isNotNull);
      expect(got!.length, 0);
    });

    test('round-trips a sub-part payload (< 1 SDU)', () async {
      final payload = _bytes(100, seed: 3);
      final got = await _runTransfer(payload);
      expect(got, isNotNull);
      expect(_sha(got!), equals(_sha(payload)));
    });

    test('rejects a permanently-corrupted part (never completes)', () async {
      final payload = _bytes(300 * 1024, seed: 9); // many parts
      final got = await _runTransfer(payload,
          corruptIndexEveryTime: 3, maxRounds: 200000);
      expect(got, isNull, reason: 'a corrupt part must never assemble as valid');
    });
  });

  group('link MTU discovery', () {
    test('negotiates the offered MTU on both ends + derived sizes scale',
        () async {
      final (initiator, responder) = await _linkPair(hwMtu: kRnsLinkMtuMax);
      // Both ends converge on the negotiated MTU.
      expect(responder.mtu, kRnsLinkMtuMax);
      expect(initiator.mtu, kRnsLinkMtuMax);
      // The part SDU scales up with the MTU (vs 464 at MTU 500); the hashmap
      // batch (HASHMAP_MAX_LEN=74) is fixed and does NOT scale.
      expect(responder.resourceSdu, greaterThan(200000));
      // A 1 MB segment now splits into a handful of big parts, not 2260.
      final sender = RnsResourceSender(responder, _bytes(1024 * 1024))
        ..prepare();
      expect(sender.parts, lessThan(10),
          reason: 'big MTU -> few parts per 1 MB segment');
    });

    test('falls back to MTU 500 when no discovery (default interface)',
        () async {
      final (initiator, responder) = await _linkPair(); // hwMtu = kRnsMtu
      expect(initiator.mtu, kRnsMtu);
      expect(responder.mtu, kRnsMtu);
      expect(responder.resourceSdu, 464); // the historical 500-MTU SDU
    });

    test('caps the link MTU at the responder return-path capability', () async {
      // Initiator offers a big MTU, but the responder's arrival interface only
      // does 500 (e.g. a BLE-reachable responder) → both must end up at 500.
      final dest = await RnsIdentity.generate();
      final initiator = await RnsLink.initiator(
          RnsIdentity.fromPublicKey(dest.getPublicKey()), 'test', ['resource']);
      initiator.offerMtu(kRnsLinkMtuMax);
      final request = initiator.buildRequest();
      final responder =
          await RnsLink.responder(dest, request, arrivalHwMtu: kRnsMtu);
      final proof = await responder.buildProof();
      final rtt = await initiator.handleProof(proof);
      expect(rtt, isNotNull);
      expect(responder.mtu, kRnsMtu);
      expect(initiator.mtu, kRnsMtu, reason: 'initiator adopts the capped value');
    });

    for (final spec in const [
      ('1 MB', 1024 * 1024),
      ('16 MB', 16 * 1024 * 1024),
      ('55 MB', 55 * 1024 * 1024),
    ]) {
      test('round-trips ${spec.$1} byte-exact at a large negotiated MTU',
          () async {
        final payload = _bytes(spec.$2, seed: spec.$2 ^ 0x5a5a);
        final got = await _runTransfer(payload, hwMtu: kRnsLinkMtuMax);
        expect(got, isNotNull, reason: '${spec.$1} did not complete');
        expect(_sha(got!), equals(_sha(payload)), reason: 'bytes differ');
      }, timeout: const Timeout(Duration(minutes: 5)));
    }
  });
}
