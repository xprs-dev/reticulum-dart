/*
 * Requests over a Reticulum link: a server answers by path, a client sends
 * many requests over one link; small ones ride single packets, large ones a
 * Resource, in both directions.
 */
import 'dart:typed_data';

import 'package:reticulum/reticulum.dart';
import 'package:test/test.dart';

void main() {
  test('one link, many requests, inline and as Resources both ways', () async {
    final station = await RnsIdentity.generate();
    final dest = RnsDestination.hash(station, 'xprs', ['wapp']);
    late RnsRequestServer server;
    late RnsRequestClient client;
    // Two ends wired straight to each other: what one sends the other gets.
    void toServer(Uint8List raw) {
      final p = RnsPacket.parse(raw);
      if (p != null) Future(() => server.handlePacket(p));
    }
    void toClient(Uint8List raw) {
      final p = RnsPacket.parse(raw);
      if (p != null) Future(() => client.handlePacket(p));
    }
    server = RnsRequestServer(identity: station, destHash: dest, send: toClient);
    final big = Uint8List.fromList(List.generate(20000, (i) => i * 7 & 0xff));
    server.register('/echo', (data, link) async => data);
    server.register('/big', (data, link) async => big);
    client = RnsRequestClient(
      peer: RnsIdentity.fromPublicKey(station.getPublicKey()),
      appName: 'xprs',
      aspects: const ['wapp'],
      send: toServer,
      nextHopForDest: (_) => null,
      hasPathForDest: (_) => true,
    );
    expect(await client.open(), isTrue);
    expect(await client.request('/echo', {'m': 'GET', 'p': '/api/status'}),
        {'m': 'GET', 'p': '/api/status'});
    final got = await client.request('/big', null);
    expect(got, isA<List<int>>());
    expect(Uint8List.fromList(got as List<int>), big);
    // A request too large for one packet goes as a Resource too.
    final up = Uint8List.fromList(List.generate(9000, (i) => i & 0xff));
    final echoed = await client.request('/echo', up);
    expect(Uint8List.fromList(echoed as List<int>), up);
    expect(await client.request('/nothing', null, timeout: const Duration(seconds: 2)), isNull);
    expect(server.openLinks, 1);
  });
}
