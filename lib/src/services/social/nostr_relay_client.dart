/*
 * NostrRelayClient — the transport abstraction.
 *
 * A "relay" is anything you can send a REQ / EVENT to and receive EVENT / EOSE /
 * OK back from. The TRANSPORT varies and is chosen by the endpoint URI scheme:
 *   wss:// | ws://   → internet WebSocket   (NostrWsClient)
 *   rns://<idhex>    → Reticulum relay      (NostrRnsClient, wraps RelayNode)
 *   local            → this device          (NostrLocalClient, RelayEventStore)
 *
 * The NostrRelayHub owns a list of these and never cares which transport a given
 * client is — so a new transport is one new implementation, zero changes above.
 */
import '../../util/nostr_event.dart';
import 'relay_event_store.dart' show NostrFilter;

enum NostrRelayStatus { disconnected, connecting, connected, error }

/// Callbacks a client raises to its owner (the hub).
typedef NostrEventCallback = void Function(String subId, NostrEvent event);
typedef NostrEoseCallback = void Function(String subId);
typedef NostrStatusCallback = void Function(NostrRelayStatus status);

/// The relay REFUSED a subscription (NIP-01 `CLOSED`): rate-limited, too many
/// filters, auth-required. Not an error on the socket — the socket is fine — so
/// nothing else in the stack would ever notice.
typedef NostrClosedCallback = void Function(String subId, String message);

abstract class NostrRelayClient {
  /// The endpoint URI this client serves (wss://…, rns://…, local).
  String get uri;

  NostrRelayStatus get status;

  /// Set by the hub before [connect]; the client calls these as data arrives.
  NostrEventCallback? onEvent;
  NostrEoseCallback? onEose;
  NostrStatusCallback? onStatus;
  NostrClosedCallback? onClosed;

  /// Open / begin maintaining the connection. Idempotent.
  Future<void> connect();

  /// Open a subscription. Matching stored + live events arrive via [onEvent];
  /// [onEose] fires once the stored backlog is delivered.
  void subscribe(String subId, List<NostrFilter> filters);

  /// Frames received since the last call (evidence that a socket is alive).
  int drainFrames() => 0;

  /// Foreground/pull-to-refresh recovery: reconnect a dead or zombie socket
  /// immediately instead of waiting out backoff. No-op for local transports.
  void resume() {}

  /// Close the socket but stay RECONNECTABLE — the subscriptions are kept and
  /// replayed on the next [connect]. This is the off-grid poll model: public
  /// relays cut a long-lived connection, so we hold one only for the seconds of
  /// a poll and drop it in between. No-op for local/RNS transports (no socket).
  void disconnect() {}

  /// Force a genuinely fresh socket: a relay that has silently dropped its half
  /// leaves ours reading "connected" forever. Assume every socket is already
  /// dead and rebuild it. No-op for local/RNS.
  Future<void> reconnectFresh() async {}

  /// Drop the connection and build it again (subscriptions are replayed).
  ///
  /// For when a relay has silently stopped answering a subscription it never
  /// closed: the socket is fine, the REQ is on the wire, and nothing arrives.
  /// Re-sending the REQ down the same connection does not bring it back.
  void reconnect() {}

  /// Cancel a subscription.
  void unsubscribe(String subId);

  /// Publish an event. Returns true if the transport accepted it for delivery
  /// (not necessarily that a remote relay stored it — that arrives as OK).
  Future<bool> publish(NostrEvent event);

  /// Tear down.
  Future<void> close();
}

/// The transport an endpoint URI selects.
enum NostrTransport { websocket, reticulum, local, unknown }

NostrTransport nostrTransportOf(String uri) {
  final u = uri.trim().toLowerCase();
  if (u == 'local' || u.startsWith('local')) return NostrTransport.local;
  if (u.startsWith('wss://') || u.startsWith('ws://')) {
    return NostrTransport.websocket;
  }
  if (u.startsWith('rns://')) return NostrTransport.reticulum;
  return NostrTransport.unknown;
}
