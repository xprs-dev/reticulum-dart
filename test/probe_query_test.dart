/*
 * The claim this whole design rests on: an empty query must cost NOTHING.
 *
 * No link, no handshake, no reply packet, and — after first contact with a peer
 * — not a single asymmetric operation. These tests assert exactly that, plus the
 * two fallbacks (peer has data; peer is an old node).
 */
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:sqlite3/open.dart';

/// The test VM has libsqlite3.so.0 but not the bare `libsqlite3.so` symlink that
/// the loader looks for by default, so point it at the real library. (Other
/// tests dodge this with fake stores; this one exercises the REAL query path,
/// because "did it actually find zero events" is the whole assertion.)
void _useSystemSqlite() {
  if (!Platform.isLinux) return;
  open.overrideFor(
      OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));
}

Future<RelayNode> _node(RelayEventStore store,
    {required List<Uint8List> sent,
    Future<({bool supported, Uint8List? body})> Function(
            RnsIdentity, Uint8List)?
        probe,
    bool serve = false,
    String? selfPub}) async {
  final id = await RnsIdentity.generate();
  return RelayNode(
    identity: id,
    store: store,
    send: sent.add,
    serve: serve,
    selfPubHex: selfPub == null ? null : () => selfPub,
    probeQuery: probe,
  );
}

void main() {
  late RelayEventStore store;

  setUpAll(_useSystemSqlite);
  setUp(() => store = RelayEventStore.open(':memory:'));
  tearDown(() => store.close());

  test('a peer that holds nothing answers with SILENCE — and we send no link',
      () async {
    final sent = <Uint8List>[];
    var probes = 0;
    final node = await _node(
      store,
      sent: sent,
      probe: (peer, req) async {
        probes++;
        // The responder found nothing, so it never replied. Silence.
        return (supported: true, body: null);
      },
    );

    final peer = await RnsIdentity.generate();
    final events = await node.query(peer, const NostrFilter(kinds: [1]));

    expect(events, isEmpty);
    expect(probes, 1);
    expect(sent, isEmpty,
        reason: 'NO packet may be sent: not a LINKREQUEST, not anything. '
            'This is the case that was 98 of 98 inbound queries.');
  });

  test('a probe that returns a RESULT is used directly — still no link',
      () async {
    final sent = <Uint8List>[];
    // Pretend the peer answered with a RESULT frame carrying no events.
    final result = RelayProtocol.result('s0', const [], true);
    final node = await _node(
      store,
      sent: sent,
      probe: (peer, req) async => (supported: true, body: result),
    );

    final peer = await RnsIdentity.generate();
    await node.query(peer, const NostrFilter(kinds: [1]));

    expect(sent, isEmpty, reason: 'a RESULT is the whole answer — no link');
  });

  test('an OLD peer (no probe support) still gets a link — interop preserved',
      () async {
    final sent = <Uint8List>[];
    final node = await _node(
      store,
      sent: sent,
      probe: (peer, req) async => (supported: false, body: null),
    );

    final peer = await RnsIdentity.generate();
    // Times out (nobody answers the link), but it must have TRIED a link.
    await node.query(peer, const NostrFilter(kinds: [1]),
        timeout: const Duration(milliseconds: 200));

    expect(sent, isNotEmpty,
        reason: 'an old peer must still be reachable the old way');
  });

  test('the responder stays silent on an empty store, and answers when it has data',
      () async {
    // A REAL signed event: the store verifies the Schnorr signature on put(),
    // so a forged fixture would be (correctly) rejected and would quietly turn
    // this into a test of nothing.
    const privHex =
        '0001a3f19c8d2b4e6f70a3f19c8d2b4e6f70a3f19c8d2b4e6f701b2c00000001';
    final selfPub = NostrCrypto.derivePublicKey(privHex);

    final sent = <Uint8List>[];
    final node = await _node(store, sent: sent, serve: true, selfPub: selfPub);

    final req = RelayProtocol.req('s1', const NostrFilter(kinds: [1]));

    // Nothing stored -> silence.
    expect(await node.answerProbe(req), isNull,
        reason: 'no data means no reply at all');

    final ev = NostrEvent(
      pubkey: selfPub,
      createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      kind: 1,
      tags: const [],
      content: 'hello',
    );
    ev.sign(privHex);
    expect(store.put(ev), isTrue, reason: 'the fixture must really be stored');

    final answer = await node.answerProbe(req);
    expect(answer, isNotNull, reason: 'we hold a match, so we speak up');
    expect(answer!.type, anyOf(NpdType.result, NpdType.have));
  });

  test('a malformed probe body is ignored, not answered', () async {
    final sent = <Uint8List>[];
    final node = await _node(store, sent: sent, serve: true);
    expect(await node.answerProbe(Uint8List.fromList([0xFF, 0x00, 0x13])),
        isNull);
  });
}
