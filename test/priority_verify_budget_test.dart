/*
 * A priority overlay announce must never be shed for want of a verify token.
 *
 * An XPRS 1:1 over Reticulum rides an announce of the sender's `xprs/wapp`
 * destination, which always carries fresh app_data and so always needs a real
 * Ed25519 verify. On a busy node (a phone that became a transport node and hears
 * the whole hub firehose) the GENERAL verify budget is spent on foreign churn,
 * and the 1:1 announce was silently dropped — the measured cause of intermittent
 * phone→phone delivery. Priority announces now draw from a SEPARATE budget, so
 * foreign load can no longer starve them. It stays a budget, not a blanket
 * exemption, because the priority test matches a public, spoofable name_hash.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Future<RnsPacket> _announce(RnsIdentity id, String app, List<String> aspects,
    {Uint8List? appData}) async {
  final p = await RnsAnnounceBuilder.build(id, app, aspects, appData: appData);
  return RnsPacket.parse(p.pack())!;
}

void main() {
  test('a priority overlay announce is verified even when the foreign verify '
      'budget is spent', () async {
    final t = RnsTransport();
    // The host registers the overlay's name_hash as priority (rns_service.dart).
    const app = 'xprs';
    const aspects = ['wapp'];
    t.priorityAnnounceNames.add(_hex(RnsDestination.nameHash(app, aspects)));

    // Spend the GENERAL verify budget: prime one foreign dest, then re-announce
    // it with churned app_data. Each churn misses the trust fast-path and draws
    // a real verify token; a known-dest re-announce skips the new-destination
    // flood budget, so this exercises the verify ceiling directly.
    final foreign = await RnsIdentity.generate();
    await t.ingest(await _announce(foreign, 'foreignapp', const ['peer']), 'tcp:hub');
    for (var i = 0; i < 16; i++) {
      final ad = Uint8List.fromList([i, i, i, i]);
      await t.ingest(
          await _announce(foreign, 'foreignapp', const ['peer'], appData: ad),
          'tcp:hub');
    }
    expect(t.verifyBudgetShed, greaterThan(0),
        reason: 'the foreign churn exhausts the general verify budget');

    // Now a priority overlay announce (a fresh sender, as an inbound 1:1 would
    // be) must STILL verify — it has its own budget — and must NOT be shed.
    final sender = await RnsIdentity.generate();
    final got = await t.ingest(await _announce(sender, app, aspects), 'tcp:hub');
    expect(got, isNotNull,
        reason: 'priority announce has its own verify budget');
    expect(t.priVerifyBudgetShed, 0,
        reason: 'no priority announce was shed by a foreign flood');
  });

  test('a forged-priority flood is still bounded (own budget, not unlimited)',
      () async {
    final t = RnsTransport();
    const app = 'xprs';
    const aspects = ['wapp'];
    t.priorityAnnounceNames.add(_hex(RnsDestination.nameHash(app, aspects)));

    // The priority name_hash is public; an attacker can forge announces bearing
    // it. Its own budget must cap the crypto they can force: after the priority
    // window fills, further priority announces are shed too.
    var shedSeen = false;
    for (var i = 0; i < 24 && !shedSeen; i++) {
      final forger = await RnsIdentity.generate();
      await t.ingest(await _announce(forger, app, aspects), 'tcp:hub');
      shedSeen = t.priVerifyBudgetShed > 0;
    }
    expect(shedSeen, isTrue,
        reason: 'the priority budget bounds a forged-name_hash flood');
  });
}
