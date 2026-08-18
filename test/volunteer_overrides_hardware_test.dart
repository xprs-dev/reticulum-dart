/*
 * The owner's decision beats the charger (aurora/docs/NOSTR.md).
 *
 * The capacity rule — charger + a real uplink ⇒ indexer — is a good default and
 * a bad only-option. The old phone in a drawer must be able to say "yes, use
 * this", and the metered home line must be able to say "no, don't".
 *
 * This is not cosmetic. Before this, picking "Always" wrote a preference and
 * changed nothing on the wire: the announce still said LEAF, every peer filed
 * the device as a leaf, and no indexer ever synced with it. A decision the
 * network never hears is not a decision.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/files/capacity_policy.dart';
import 'package:reticulum/src/services/social/relay_role.dart';

const _onBattery = CapacityProfile(
  capacity: 5,
  servingAllowed: true,
  unlimited: false, // not plugged in: the hardware says "leaf"
  dailyBudgetBytes: 100 << 20,
);

const _plugged = CapacityProfile(
  capacity: 2,
  servingAllowed: true,
  unlimited: true,
  dailyBudgetBytes: 1 << 30,
);

void main() {
  test('auto: the hardware decides, as before', () {
    final m = RelayRoleManager()..volunteer = 'auto';
    m.applyCapacity(_onBattery);
    expect(m.current.isIndexer, isFalse);
    m.applyCapacity(_plugged);
    expect(m.current.isIndexer, isTrue);
  });

  test('always: a phone in a drawer can volunteer, and the announce SAYS so',
      () {
    final m = RelayRoleManager()..volunteer = 'always';
    m.applyCapacity(_onBattery);
    expect(m.current.isIndexer, isTrue,
        reason: 'the owner said yes; the charger does not get a veto');
    expect(m.current.has(RelayCap.search), isTrue,
        reason: 'and it advertises that it can be synced with — otherwise no '
            'indexer would ever talk to it');

    // The decision has to survive the round trip, because that is the only part
    // the network ever sees.
    final back = RelayAnnouncement.decode(m.current.encode())!;
    expect(back.isIndexer, isTrue);
    expect(back.has(RelayCap.search), isTrue);
  });

  test('off: the metered line stops serving, whatever the charger says', () {
    final m = RelayRoleManager()..volunteer = 'off';
    m.applyCapacity(_plugged);
    expect(m.current.isIndexer, isFalse);
    expect(m.current.has(RelayCap.search), isFalse,
        reason: 'revoking must be as effective as granting');
  });

  test('changing the decision changes the announcement', () {
    final m = RelayRoleManager()..volunteer = 'auto';
    m.applyCapacity(_onBattery);
    expect(m.current.isIndexer, isFalse);

    m.volunteer = 'always';
    m.applyCapacity(_onBattery);
    expect(m.current.isIndexer, isTrue);

    m.volunteer = 'off';
    m.applyCapacity(_plugged);
    expect(m.current.isIndexer, isFalse);
  });
}
