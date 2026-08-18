/*
 * putAllVerified is the ONLY way into the store that skips signature
 * verification, and it exists for one reason: the follows mirror runs on the
 * isolate that owns this store (the app's main/UI isolate), and re-verifying
 * events the nostr-engine isolate already verified would put secp256k1 back on
 * the UI thread — the pattern that once froze the app for hours
 * (aurora/docs/performance.md §3.1).
 *
 * That makes it a security-relevant shortcut, so the property that matters is
 * not "the batch is fast" but "the shortcut did not leak into the normal path":
 * anything arriving off the wire must still be rejected if its signature is
 * forged. Both halves are asserted here.
 */
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:sqlite3/open.dart';

void _useSystemSqlite() {
  if (!Platform.isLinux) return;
  open.overrideFor(
      OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));
}

const _privHex =
    '0001a3f19c8d2b4e6f70a3f19c8d2b4e6f70a3f19c8d2b4e6f701b2c00000001';

NostrEvent _signed(String pub, {required int kind, required String content, int? at}) {
  final ev = NostrEvent(
    pubkey: pub,
    createdAt: at ?? DateTime.now().millisecondsSinceEpoch ~/ 1000,
    kind: kind,
    tags: const [],
    content: content,
  );
  ev.sign(_privHex);
  return ev;
}

void main() {
  late RelayEventStore store;
  late String pub;

  setUpAll(_useSystemSqlite);

  setUp(() {
    store = RelayEventStore.open(':memory:');
    pub = NostrCrypto.derivePublicKey(_privHex);
  });

  tearDown(() => store.close());

  test('putAllVerified stores a batch, tiered, and is queryable afterwards', () {
    final batch = [
      for (var i = 0; i < 5; i++)
        _signed(pub, kind: 1, content: 'note $i', at: 1752300000 + i),
    ];

    final stored = store.putAllVerified(batch, tier: 1); // 1 = followed
    expect(stored, 5);

    final back = store.query(NostrFilter(kinds: const [1], authors: [pub]));
    expect(back.length, 5,
        reason: 'a batched write must be as visible as a single one — this is '
            'what RelayNode serves to peers');
  });

  test('a duplicate inside the batch is stored once, and the rest still land', () {
    final ev = _signed(pub, kind: 1, content: 'same', at: 1752300000);
    final other = _signed(pub, kind: 1, content: 'different', at: 1752300001);

    expect(store.putAllVerified([ev, ev, other], tier: 1), 2);
    expect(store.query(NostrFilter(kinds: const [1], authors: [pub])).length, 2);
  });

  test('the batch path really does skip verification (that is its whole point)',
      () {
    final ev = _signed(pub, kind: 1, content: 'trusted', at: 1752300000);
    // Corrupt the signature AFTER signing. put() would reject this; the batch
    // path must not even look, or it would be paying the crypto we are avoiding.
    ev.sig = 'f' * 128;

    expect(store.putAllVerified([ev], tier: 1), 1,
        reason: 'no Schnorr check on the trusted in-process path');
  });

  test('put() STILL rejects a forged signature — the shortcut did not leak', () {
    final ev = _signed(pub, kind: 1, content: 'forged', at: 1752300000);
    ev.sig = 'f' * 128;

    expect(store.put(ev), isFalse,
        reason: 'events off the wire must always be verified');
    expect(store.query(NostrFilter(kinds: const [1], authors: [pub])), isEmpty);
  });

  test('put() still rejects an event whose id does not match its content', () {
    // A validly-signed event, then the same (id, sig) re-attached to different
    // content — the classic tamper. verify() recomputes the id, so it must fail.
    final real = _signed(pub, kind: 1, content: 'original', at: 1752300000);
    final tampered = NostrEvent(
      id: real.id,
      pubkey: pub,
      createdAt: 1752300000,
      kind: 1,
      tags: const [],
      content: 'tampered',
      sig: real.sig,
    );

    expect(store.put(tampered), isFalse);
  });

  test('an empty batch is a no-op (and does not open a transaction)', () {
    expect(store.putAllVerified(const [], tier: 1), 0);
    // A stray open transaction would make this next write throw.
    expect(store.put(_signed(pub, kind: 1, content: 'after', at: 1752300002)),
        isTrue);
  });
}
