/*
 * Bandwidth belongs to the owner of the device (aurora/docs/NOSTR.md).
 *
 * A hostile client cannot delete what you kept — the tier partition sees to
 * that — but it can absolutely make your phone push gigabytes to strangers over
 * a plan you are paying for. So serving is identity-aware: the people you know
 * are unmetered, and everybody else shares a budget you set.
 */
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/files/serve_quota.dart';

final _sha = Uint8List.fromList(List.filled(32, 7));

void main() {
  const friend = 'friend-pub';
  const stranger = 'stranger-pub';
  const otherStranger = 'other-stranger-pub';

  ServeQuota quota({int strangerBudget = 1000, bool allowed = true}) =>
      ServeQuota(
        dailyBudgetBytes: 100000,
        perRequesterBytes: 100000,
        strangerDailyBudgetBytes: strangerBudget,
        servingAllowed: allowed,
        trustOf: (r) => r == friend ? Requester.trusted : Requester.stranger,
      );

  test('a friend is unmetered — handing their data back is the whole point',
      () {
    final q = quota(strangerBudget: 0);
    for (var i = 0; i < 50; i++) {
      expect(q.canServe(friend, _sha, 10000), isTrue);
      q.record(friend, _sha, 10000);
    }
    expect(q.strangerBytesServedToday, 0);
  });

  test("'don't serve strangers on cellular' never means 'ignore my own phone'",
      () {
    final q = quota(allowed: false); // the cellular hard-off
    expect(q.canServe(stranger, _sha, 1), isFalse);
    expect(q.canServe(friend, _sha, 4 << 20), isTrue,
        reason: 'my other device asking for my own data is not an abuse case');
  });

  test('strangers share one budget, and it actually stops them', () {
    final q = quota(strangerBudget: 1000);
    expect(q.canServe(stranger, _sha, 600), isTrue);
    q.record(stranger, _sha, 600);
    expect(q.canServe(otherStranger, _sha, 600), isFalse,
        reason: 'one npub cannot spend it, and a thousand cannot either');
    expect(q.canServe(otherStranger, _sha, 400), isTrue);
  });

  test('a stranger budget of zero means exactly that', () {
    final q = quota(strangerBudget: 0);
    expect(q.canServe(stranger, _sha, 1), isFalse);
    expect(q.canServe(friend, _sha, 1), isTrue);
  });

  test('with no trust lookup, everyone is a stranger — the safe reading', () {
    final q = ServeQuota(strangerDailyBudgetBytes: 100);
    expect(q.canServe(friend, _sha, 500), isFalse,
        reason: 'we were never told who this is, so we assume nothing');
  });

  test('status reports the stranger budget the owner set, and its use', () {
    final q = quota(strangerBudget: 1000);
    q.record(stranger, _sha, 250);
    q.record(friend, _sha, 900);
    final s = q.status();
    expect(s['strangerBudget'], 1000);
    expect(s['strangerServedToday'], 250,
        reason: "the friend's 900 bytes are not the strangers' problem");
  });
}
