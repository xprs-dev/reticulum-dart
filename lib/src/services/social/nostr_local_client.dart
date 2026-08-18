/*
 * NostrLocalClient — the "this device" transport. A relay that is simply the
 * local RelayEventStore: subscriptions answer from the stored backlog, publishes
 * write straight to the store. Always "connected" (no network). This is what
 * makes the device itself a relay from the client's point of view; it is ALSO
 * served to other devices over Reticulum (RelayNode) and, when enabled, over a
 * local wss server (nostr_ws_server.dart).
 */
import 'dart:async';

import '../../util/nostr_event.dart';
import 'nostr_relay_client.dart';
import 'nostr_relay_hub.dart' show NostrStore;
import 'relay_event_store.dart' show NostrFilter;

class NostrLocalClient implements NostrRelayClient {
  final NostrStore store;
  @override
  final String uri;

  NostrLocalClient(this.store, {this.uri = 'local'});

  @override
  NostrEventCallback? onEvent;
  @override
  NostrEoseCallback? onEose;
  @override
  NostrClosedCallback? onClosed;
  @override
  NostrStatusCallback? onStatus;

  @override
  NostrRelayStatus get status => NostrRelayStatus.connected;

  @override
  Future<void> connect() async => onStatus?.call(NostrRelayStatus.connected);

  @override
  void subscribe(String subId, List<NostrFilter> filters) {
    // Answer from the local store, then EOSE. Live local events reach the hub
    // through its own put() path, so they don't need to be re-emitted here.
    for (final f in filters) {
      for (final e in store.query(f)) {
        e.preVerified = true; // verified once, at insert; not again
        onEvent?.call(subId, e);
      }
    }
    onEose?.call(subId);
  }

  @override
  int drainFrames() => 0;
  @override
  void resume() {}
  @override
  void disconnect() {}
  @override
  Future<void> reconnectFresh() async {}

  @override
  void reconnect() {} // no socket to cycle

  @override
  void unsubscribe(String subId) {}

  @override
  Future<bool> publish(NostrEvent event) async => store.put(event, tier: 0);

  @override
  Future<void> close() async {}
}
