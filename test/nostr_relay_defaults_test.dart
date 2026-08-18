/*
 * A device must not be stranded on a dead relay list.
 *
 * The hub used to seed kDefaultNostrRelays only when the persisted list was
 * EMPTY. So an install made before a relay was added to the defaults never got
 * it, and an install whose relays had since died (unreachable, or serving no
 * firehose) stayed dead forever — a phone was found with two relays, both
 * useless, showing a feed sixteen hours old.
 *
 * Merging on every start fixes that, but must not resurrect a relay the user
 * threw away. These tests pin both halves.
 */
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';

class _Store implements NostrStore {
  @override
  bool put(NostrEvent e, {int tier = 2}) => true;
  @override
  List<NostrEvent> query(NostrFilter f) => const [];
  @override
  bool addReaction(String eventId, String pubkey) => true;
  @override
  List<String> reactionPubkeys(String eventId) => const [];
  @override
  List<String> replyIdsFor(String eventId) => const [];
}

void main() {
  late Directory dir;
  late String persist;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('relaydef');
    persist = '${dir.path}/relays.json';
  });
  tearDown(() => dir.deleteSync(recursive: true));

  // `local` and rns:// build no sockets, so they stand in for "a real relay"
  // without the test touching the network.
  const rnsA = 'rns://aaaa';
  const rnsB = 'rns://bbbb';

  NostrRelayHub hub(List<String> defaults) => NostrRelayHub(
        store: _Store(),
        persistPath: persist,
        defaultRelays: defaults,
        rnsClientFactory: (_) => null,
      );

  List<String> uris(NostrRelayHub h) =>
      [for (final e in h.relaysJson()) e['uri'] as String];

  test('first run seeds the defaults', () async {
    final h = hub(const ['local', rnsA]);
    await h.init();
    expect(uris(h), containsAll(['local', rnsA]));
    await h.close();
  });

  test('a default added LATER reaches a device that already has a list',
      () async {
    File(persist).writeAsStringSync(jsonEncode([
      {'uri': 'local'},
    ]));

    final h = hub(const ['local', rnsA]); // rnsA is new to this device
    await h.init();
    expect(uris(h), containsAll(['local', rnsA]),
        reason: 'the stranded device must be handed the relay it never had');
    await h.close();
  });

  test('a default the user REMOVED is not resurrected', () async {
    // Run once: the device is offered both.
    final first = hub(const ['local', rnsA, rnsB]);
    await first.init();
    expect(first.removeRelay(rnsB), true);
    await first.close();

    // Run again with the same defaults: rnsB was offered once and thrown away.
    final second = hub(const ['local', rnsA, rnsB]);
    await second.init();
    expect(uris(second), containsAll(['local', rnsA]));
    expect(uris(second), isNot(contains(rnsB)),
        reason: 'offered-and-removed is not the same as never-offered');
    await second.close();
  });

  test('a default the user DISABLED stays disabled', () async {
    final first = hub(const ['local', rnsA]);
    await first.init();
    expect(first.setRelayEnabled(rnsA, false), true);
    await first.close();

    final second = hub(const ['local', rnsA]);
    await second.init();
    final e = second.relaysJson().firstWhere((e) => e['uri'] == rnsA);
    expect(e['enabled'], false);
    await second.close();
  });
}
