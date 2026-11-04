/*
 * Answered LXMF links are bounded.
 *
 * Every inbound link request used to leave its link and session state in
 * LxmfRouter._in for the life of the process — nothing ever removed one, and
 * anybody can send a link request (audit 2026-11-04, docs/performance.md 8.18).
 * The table is now swept on each accept: a closed link goes at once, an idle
 * one after LxmfRouter.inboundIdle, and the least recently used once
 * LxmfRouter.inboundCap are held.
 */
import 'package:test/test.dart';
import 'package:reticulum/reticulum.dart';

void main() {
  test('inbound links stay under the cap however many strangers ask', () async {
    final me = await RnsIdentity.generate();
    final router = LxmfRouter(identity: me, send: (_) {}, identityForDest: (_) => null);
    const asks = LxmfRouter.inboundCap + 40;
    for (var n = 0; n < asks; n++) {
      // A fresh initiator each time: a new link id, as a stranger's would be.
      final link = await RnsLink.initiator(me, kLxmfApp, kLxmfDeliveryAspects);
      await router.handlePacket(link.buildRequest());
    }
    expect(router.inboundLinks, lessThanOrEqualTo(LxmfRouter.inboundCap));
    expect(router.inboundEvicted, greaterThanOrEqualTo(asks - LxmfRouter.inboundCap));
  });
}
