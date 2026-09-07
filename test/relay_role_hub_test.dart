/*
 * A node on mains power with a fixed link (an "unlimited" CapacityProfile) is
 * promoted to a TRANSPORT hub for its neighbours and says so in its relay
 * announcement; a battery/cellular node stays a leaf and never advertises it.
 * The transport-node rebroadcast rules themselves are locked by
 * edge_bridge_test.dart; this locks the capacity→role gate that turns them on.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/files/capacity_policy.dart';
import 'package:reticulum/src/services/social/relay_role.dart';

CapacityProfile _situation(NetKind net, bool charging) =>
    policyFor(net, charging, serveOnCellular: false, quotaMb: 1024);

void main() {
  final interests = InterestSet();

  test('an unlimited (mains + Wi-Fi) node advertises the transport-hub cap', () {
    final p = _situation(NetKind.wifi, true);
    expect(p.unlimited, isTrue);
    final a = RelayAnnouncement.forCapacity(p, interests);
    expect(a.isIndexer, isTrue);
    expect(a.caps & RelayCap.transport, isNot(0),
        reason: 'the node that can index can also forward for its neighbours');
  });

  test('a battery node on cellular stays a leaf with no transport cap', () {
    final p = _situation(NetKind.cellular, false);
    expect(p.unlimited, isFalse);
    final a = RelayAnnouncement.forCapacity(p, interests);
    expect(a.isIndexer, isFalse);
    expect(a.caps & RelayCap.transport, 0,
        reason: 'a pocket device is never volunteered as a hub');
  });

  test('a Wi-Fi node NOT on charger is not unlimited, so not a hub', () {
    final p = _situation(NetKind.wifi, false);
    expect(p.unlimited, isFalse);
    expect(RelayAnnouncement.forCapacity(p, interests).caps & RelayCap.transport,
        0);
  });
}
