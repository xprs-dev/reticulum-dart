/*
 * NostrWsServer — the device's public wss:// front door.
 *
 * What matters here is not "the socket speaks JSON" but the relay contract the
 * rest of the system now leans on:
 *  - REQ replays the store then EOSE, and the sub STAYS OPEN: events stored
 *    later (any transport — wired via RelayEventStore.onPut → broadcast) are
 *    live-pushed to it. This is how a mailto resolution answer reaches the
 *    requester after EOSE.
 *  - WS-inbound EVENTs run the same admission chain as the mesh door (spam
 *    policy, tier, admitEvent veto) — the WS path must not be the bypass.
 *  - kind-4 encrypted DMs never leave over the public socket by default.
 *  - A REQ for kind-30078 #d "mailto:…" with nothing stored triggers the
 *    host's resolveMailto exactly once per address.
 */
import 'dart:async';
import 'dart:convert';
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

NostrEvent _signed(
  String pub, {
  required int kind,
  required String content,
  int? at,
  List<List<String>> tags = const [],
}) {
  final ev = NostrEvent(
    pubkey: pub,
    createdAt: at ?? DateTime.now().millisecondsSinceEpoch ~/ 1000,
    kind: kind,
    tags: tags,
    content: content,
  );
  ev.sign(_privHex);
  return ev;
}

/// Collects incoming frames; [next] waits for the following one.
class _WsProbe {
  final WebSocket ws;
  final _frames = StreamController<List<dynamic>>();
  late final StreamQueueLike q = StreamQueueLike(_frames.stream);
  _WsProbe(this.ws) {
    ws.listen((data) {
      _frames.add(jsonDecode(data as String) as List<dynamic>);
    }, onDone: _frames.close);
  }
  void send(Object frame) => ws.add(jsonEncode(frame));
  Future<void> close() => ws.close();
}

/// Minimal StreamQueue substitute (avoids a package:async dependency).
class StreamQueueLike {
  final _buffer = <List<dynamic>>[];
  final _waiters = <Completer<List<dynamic>>>[];
  StreamQueueLike(Stream<List<dynamic>> s) {
    s.listen((f) {
      if (_waiters.isNotEmpty) {
        _waiters.removeAt(0).complete(f);
      } else {
        _buffer.add(f);
      }
    });
  }

  Future<List<dynamic>> next(
      {Duration timeout = const Duration(seconds: 5)}) {
    if (_buffer.isNotEmpty) return Future.value(_buffer.removeAt(0));
    final c = Completer<List<dynamic>>();
    _waiters.add(c);
    return c.future.timeout(timeout);
  }
}

Future<_WsProbe> _connect(NostrWsServer srv) async =>
    _WsProbe(await WebSocket.connect('ws://127.0.0.1:${srv.boundPort}'));

void main() {
  late RelayEventStore store;
  late String pub;
  NostrWsServer? srv;

  setUpAll(_useSystemSqlite);

  setUp(() {
    store = RelayEventStore.open(':memory:');
    pub = NostrCrypto.derivePublicKey(_privHex);
  });

  tearDown(() async {
    await srv?.stop();
    srv = null;
    store.close();
  });

  Future<NostrWsServer> serve(NostrWsServer s) async {
    srv = s;
    expect(await s.start(), isTrue);
    // Host wiring under test: every store ingest live-pushes to WS subs.
    store.onPut = s.broadcast;
    return s;
  }

  test('REQ replays stored events then EOSE', () async {
    store.put(_signed(pub, kind: 1, content: 'hello', at: 1752300000));
    final s = await serve(NostrWsServer(store, port: 0));
    final c = await _connect(s);

    c.send(['REQ', 's1', {'kinds': [1]}]);
    final ev = await c.q.next();
    expect(ev[0], 'EVENT');
    expect(ev[1], 's1');
    expect((ev[2] as Map)['content'], 'hello');
    expect((await c.q.next())[0], 'EOSE');
    await c.close();
  });

  test('sub stays open: a later store.put is live-pushed (onPut → broadcast)',
      () async {
    final s = await serve(NostrWsServer(store, port: 0));
    final c = await _connect(s);

    c.send(['REQ', 's1', {'kinds': [1]}]);
    expect((await c.q.next())[0], 'EOSE');

    // Simulates an event arriving over ANY other transport (mesh, publish…).
    store.put(_signed(pub, kind: 1, content: 'late note', at: 1752300010));

    final ev = await c.q.next();
    expect(ev[0], 'EVENT');
    expect((ev[2] as Map)['content'], 'late note');
    await c.close();
  });

  test('EVENT: verified + stored → OK true; admitEvent veto → OK false + reason',
      () async {
    String? veto;
    final s = await serve(NostrWsServer(
      store,
      port: 0,
      admitEvent: (e, tier) => veto,
    ));
    final c = await _connect(s);

    final good = _signed(pub, kind: 1, content: 'in', at: 1752300000);
    c.send(['EVENT', good.toJson()]);
    var ok = await c.q.next();
    expect(ok[0], 'OK');
    expect(ok[2], isTrue);
    expect(store.query(NostrFilter(kinds: const [1])).length, 1);

    veto = 'not hosted here';
    final second = _signed(pub, kind: 1, content: 'out', at: 1752300001);
    c.send(['EVENT', second.toJson()]);
    ok = await c.q.next();
    expect(ok[2], isFalse);
    expect(ok[3], contains('not hosted here'));
    expect(store.query(NostrFilter(kinds: const [1])).length, 1,
        reason: 'vetoed event must not be stored');
    await c.close();
  });

  test('forged signature → OK false, nothing stored', () async {
    final s = await serve(NostrWsServer(store, port: 0));
    final c = await _connect(s);

    final forged = _signed(pub, kind: 1, content: 'forged', at: 1752300000);
    forged.sig = 'f' * 128;
    c.send(['EVENT', forged.toJson()]);
    final ok = await c.q.next();
    expect(ok[2], isFalse);
    expect(store.query(NostrFilter(kinds: const [1])), isEmpty);
    await c.close();
  });

  test('SpamPolicy rate limit rejects over-quota WS events', () async {
    final s = await serve(NostrWsServer(
      store,
      port: 0,
      spam: SpamPolicy(maxEventsPerWindow: 2),
    ));
    final c = await _connect(s);

    for (var i = 0; i < 3; i++) {
      c.send([
        'EVENT',
        _signed(pub, kind: 1, content: 'n$i', at: 1752300000 + i).toJson()
      ]);
    }
    expect((await c.q.next())[2], isTrue);
    expect((await c.q.next())[2], isTrue);
    final third = await c.q.next();
    expect(third[2], isFalse);
    expect(third[3], contains('rate limited'));
    await c.close();
  });

  test('kind-4 DMs are excluded from replay and live push by default',
      () async {
    store.put(_signed(pub, kind: 4, content: 'ciphertext', at: 1752300000));
    final s = await serve(NostrWsServer(store, port: 0));
    final c = await _connect(s);

    c.send(['REQ', 's1', {}]);
    expect((await c.q.next())[0], 'EOSE',
        reason: 'stored DM must not be replayed');

    store.put(_signed(pub, kind: 4, content: 'more', at: 1752300001));
    store.put(_signed(pub, kind: 1, content: 'public', at: 1752300002));
    final ev = await c.q.next();
    expect((ev[2] as Map)['kind'], 1,
        reason: 'only the public note may be pushed, never the DM');
    await c.close();
  });

  test('mailto REQ on empty store triggers resolveMailto; answer arrives on '
      'the open sub after EOSE', () async {
    final resolved = <String>[];
    final s = await serve(NostrWsServer(
      store,
      port: 0,
      resolveMailto: (email) async {
        resolved.add(email);
        // Fake host resolver: store the signed mapping — delivery must happen
        // purely via onPut → broadcast on the still-open sub.
        store.put(_signed(
          pub,
          kind: NostrEventKind.applicationSpecificData,
          content: jsonEncode({'email': email, 'npub': pub}),
          at: 1752300000,
          tags: [
            ['d', 'mailto:$email']
          ],
        ));
      },
    ));
    final c = await _connect(s);

    c.send([
      'REQ', 'm1',
      {'kinds': [NostrEventKind.applicationSpecificData],
       '#d': ['mailto:alice@acme.com']}
    ]);
    expect((await c.q.next())[0], 'EOSE');

    final ev = await c.q.next();
    expect(ev[0], 'EVENT');
    expect(ev[1], 'm1');
    expect(jsonDecode((ev[2] as Map)['content'] as String)['email'],
        'alice@acme.com');
    expect(resolved, ['alice@acme.com']);
    await c.close();
  });

  test('mailto REQ with a stored mapping does NOT re-trigger the resolver',
      () async {
    store.put(_signed(
      pub,
      kind: NostrEventKind.applicationSpecificData,
      content: '{"email":"bob@acme.com"}',
      at: 1752300000,
      tags: [
        ['d', 'mailto:bob@acme.com']
      ],
    ));
    final resolved = <String>[];
    final s = await serve(NostrWsServer(
      store,
      port: 0,
      resolveMailto: (email) async => resolved.add(email),
    ));
    final c = await _connect(s);

    c.send([
      'REQ', 'm1',
      {'kinds': [NostrEventKind.applicationSpecificData],
       '#d': ['mailto:bob@acme.com']}
    ]);
    expect((await c.q.next())[0], 'EVENT');
    expect((await c.q.next())[0], 'EOSE');
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(resolved, isEmpty);
    await c.close();
  });

  test('NIP-11 GET serves the host-supplied document', () async {
    final s = await serve(NostrWsServer(
      store,
      port: 0,
      relayInfo: () => {
        'name': 'geogram',
        'pubkey': pub,
        'software': 'geogram-aurora',
        'supported_nips': [1, 9, 11, 50],
      },
    ));
    final rsp = await HttpClient()
        .getUrl(Uri.parse('http://127.0.0.1:${s.boundPort}/'))
        .then((r) => r.close());
    final body = jsonDecode(await rsp.transform(utf8.decoder).join());
    expect(body['pubkey'], pub);
    expect(rsp.headers.contentType?.subType, 'nostr+json');
  });

  test('NIP-11 document with non-ASCII text still answers', () async {
    // Regression: the response carries no charset, so writing the document as
    // a String encoded it as latin-1 and a single em-dash threw inside the
    // async handler — the connection was never closed and every probe hung
    // until it timed out. Caught only on a real device.
    final s = await serve(NostrWsServer(
      store,
      port: 0,
      relayInfo: () => {
        'name': 'geogram',
        'description': 'device relay — REQ kind 30078 #d mailto:<email>',
      },
    ));
    final rsp = await HttpClient()
        .getUrl(Uri.parse('http://127.0.0.1:${s.boundPort}/'))
        .then((r) => r.close())
        .timeout(const Duration(seconds: 5));
    final body = jsonDecode(await rsp.transform(utf8.decoder).join());
    expect(body['description'], contains('—'));
  });

  test('onPut fires from put() and post-commit from putAllVerified()', () {
    final seen = <String>[];
    store.onPut = (e) => seen.add(e.content);

    store.put(_signed(pub, kind: 1, content: 'single', at: 1752300000));
    expect(seen, ['single']);

    store.putAllVerified([
      _signed(pub, kind: 1, content: 'batch-1', at: 1752300001),
      _signed(pub, kind: 1, content: 'batch-2', at: 1752300002),
    ]);
    expect(seen, ['single', 'batch-1', 'batch-2']);

    // A rejected event (duplicate) must not fire the hook.
    store.put(_signed(pub, kind: 1, content: 'single', at: 1752300000));
    expect(seen.length, 3);
  });
}
