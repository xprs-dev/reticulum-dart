/*
 * "These N devices have it" — and enough about each that the caller does not
 * have to guess (aurora/docs/NOSTR.md, "What an Indexer actually answers").
 *
 * The redundancy is the point. What is NOT the point is making a client pick
 * blind and burn somebody's cellular data on a coin flip.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/files/dht/holder_hint.dart';
import 'package:reticulum/reticulum.dart';

import 'dart:typed_data';

Uint8List _pub(int seed) => Uint8List.fromList(List.filled(64, seed));

void main() {
  const mainsBox = HolderHint(
    lastHeardSec: 40,
    source: HintSource.direct,
    power: 4, // grid
    uplink: 1, // fibre
  );

  const phoneOnCellular = HolderHint(
    lastHeardSec: 40,
    source: HintSource.direct,
    power: 6, // battery only
    uplink: 3, // cellular
  );

  const rumour = HolderHint(
    lastHeardSec: 40,
    source: HintSource.synced,
    power: 4,
    uplink: 1,
  );

  test('the mains box is called, and the phone on cellular is left alone', () {
    expect(scoreHolder(mainsBox), greaterThan(scoreHolder(phoneOnCellular)),
        reason: 'somebody is paying for that phone by the megabyte');
  });

  test('a holder heard three weeks ago is a lottery ticket', () {
    const stale = HolderHint(lastHeardSec: 0xffff, power: 4, uplink: 1);
    expect(scoreHolder(stale), lessThan(scoreHolder(mainsBox)));
  });

  test('second-hand freshness is discounted — a rumour is still a rumour', () {
    expect(scoreHolder(rumour), lessThan(scoreHolder(mainsBox)),
        reason: 'after a sync, the age of the information is not the age of '
            'the device');
  });

  test('a holder I have no way of reaching is not a holder', () {
    const loraOnly = HolderHint(
      lastHeardSec: 40,
      power: 0,
      uplink: 4, // offgrid
      links: 1, // LoRa
    );
    final toLoraCaller = scoreHolder(loraOnly, callerLinks: 1);
    final toBluetoothCaller = scoreHolder(loraOnly, callerLinks: 2);
    expect(toLoraCaller, greaterThan(toBluetoothCaller));
  });

  test('a hint round-trips through the wire, six bytes of it', () {
    const h = HolderHint(
      lastHeardSec: 1234,
      source: HintSource.synced,
      power: 0,
      uplink: 0,
      links: 0x0009,
    );
    final b = h.encode();
    expect(b, hasLength(HolderHint.wireLen));
    final back = HolderHint.decode(b, 0);
    expect(back.lastHeardSec, 1234);
    expect(back.isSecondHand, isTrue);
    expect(back.power, 0);
    expect(back.uplink, 0);
    expect(back.links, 0x0009);
  });

  test('hints ride the VALUE reply, and a node that sends none is not broken',
      () async {
    final id = await RnsIdentity.generate();
    final rec = await ProviderRecord.create(
      providerIdentity: id,
      sha256: Uint8List.fromList(List.filled(32, 3)),
      capacity: 2,
    );

    // With hints.
    final withHints =
        DhtMessage.valueRecords(_pub(1), [rec], hints: const [mainsBox]);
    final back = DhtMessage.decode(withHints.encode())!;
    expect(back.records, hasLength(1));
    expect(back.hints, hasLength(1));
    expect(back.hints.first.uplink, 1);

    // Without: an older peer, or one with nothing to say. Still decodes.
    final bare = DhtMessage.valueRecords(_pub(1), [rec]);
    final backBare = DhtMessage.decode(bare.encode())!;
    expect(backBare.records, hasLength(1));
    expect(backBare.hints, isEmpty,
        reason: 'no hints is not an error — it is just less help');
  });
}
