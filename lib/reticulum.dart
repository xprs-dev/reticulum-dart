/// Reticulum — pure-Dart network + user protocol stack.
///
/// Reticulum transport/identity/links, NOSTR identity & notes, LXMF
/// messaging, a distributed social relay, a DHT and content-addressed file
/// sharing. See README.md for an overview.
library;

// ── Reticulum transport / protocol ──────────────────────────────────────
export 'src/services/reticulum/rns_crypto.dart';
export 'src/services/reticulum/rns_identity.dart';
export 'src/services/reticulum/rns_packet.dart';
export 'src/services/reticulum/rns_hdlc.dart';
export 'src/services/reticulum/rns_link.dart';
export 'src/services/reticulum/rns_resource.dart';
export 'src/services/reticulum/rns_resource_receiver.dart';
export 'src/services/reticulum/rns_announce.dart';
export 'src/services/reticulum/rns_transport.dart';
export 'src/services/reticulum/rns_transport_engine.dart';
export 'src/services/reticulum/rns_tcp_interface.dart';
export 'src/services/reticulum/rns_tcp_server_interface.dart';
export 'src/services/reticulum/rns_udp_interface.dart';
export 'src/services/reticulum/rns_auto_interface.dart';

// ── LXMF messaging ──────────────────────────────────────────────────────
export 'src/services/reticulum/lxmf/lxmf.dart';
export 'src/services/reticulum/lxmf/lxmf_message.dart';
export 'src/services/reticulum/lxmf/lxmf_msgpack.dart';
export 'src/services/reticulum/lxmf/lxmf_router.dart';
export 'src/services/reticulum/nomad_node.dart';

// ── NOSTR identity & notes ──────────────────────────────────────────────
export 'src/util/nostr_crypto.dart';
export 'src/util/nostr_event.dart';
export 'src/util/nostr_key_generator.dart';
export 'src/util/nostr_nip19.dart';
export 'src/util/media_ref.dart';
export 'src/util/media_archive.dart';
export 'src/util/db_opener.dart';

// ── Social relay (distributed user protocol) ────────────────────────────
export 'src/services/social/feed_quality.dart';
export 'src/services/social/firehose_curator.dart';
export 'src/services/social/file_meta.dart';
export 'src/services/social/follow_set.dart';
export 'src/services/social/host_retention_policy.dart';
export 'src/services/social/relay_event_store.dart';
export 'src/services/social/relay_node.dart';
export 'src/services/social/relay_protocol.dart';
export 'src/services/social/relay_role.dart';
export 'src/services/social/nostr_wire.dart';
export 'src/services/social/nostr_relay_client.dart';
export 'src/services/social/nostr_ws_client.dart';
export 'src/services/social/nostr_rns_client.dart';
export 'src/services/social/nostr_local_client.dart';
export 'src/services/social/nostr_relay_hub.dart';
export 'src/services/social/nostr_ws_server.dart';
export 'src/services/social/blossom_server.dart';
export 'src/services/social/nostr_engine.dart';
export 'src/services/social/retention_tier.dart';
export 'src/services/social/spam.dart';
export 'src/services/social/store_forward.dart';

// ── Participation coin (Chaumian ecash + permissioned ATM ledger) ───────
// WIP; the Aurora coin host bridges consume these directly.
export 'src/services/coin/coin_ec.dart';
export 'src/services/coin/coin_keyset.dart';
export 'src/services/coin/bearer_token.dart';
export 'src/services/coin/mint.dart';
export 'src/services/coin/wallet.dart';
export 'src/services/coin/authority_log.dart';
export 'src/services/coin/atm_chain.dart';
export 'src/services/coin/fraud.dart';
export 'src/services/coin/node_policy.dart';
export 'src/services/coin/postage.dart';
export 'src/services/coin/postage_gate.dart';
export 'src/services/coin/faucet.dart';
export 'src/services/coin/coin_service.dart';

// ── DHT ─────────────────────────────────────────────────────────────────
export 'src/services/files/dht/dht_core.dart';
export 'src/services/files/dht/dht_message.dart';
export 'src/services/files/dht/dht_node.dart';
export 'src/services/files/dht/provider_record.dart';
export 'src/services/files/dht/routing_table.dart';

// ── Content-addressed file sharing ──────────────────────────────────────
export 'src/services/files/capacity_policy.dart';
export 'src/services/files/composite_file_source.dart';
export 'src/services/files/disk_index.dart';
export 'src/services/files/file_manifest.dart';
export 'src/services/files/file_node.dart';
export 'src/services/files/file_transfer.dart';
export 'src/services/files/media_file_source.dart';
export 'src/services/files/partial_store.dart';
// provider_connection.dart removed — superseded by whole-file Resource transfer.
export 'src/services/files/serve_quota.dart';
export 'src/services/files/serve_stats.dart';

// ── XPRS crypto (compact secp256k1 Schnorr, ECDH, base85) ───────────────
export 'src/util/xprs_crypto.dart';
export 'src/util/npd.dart';

// ── BLE transport primitives (Flutter) ──────────────────────────────────
export 'src/services/reticulum/rns_ble_interface.dart';
export 'src/connections/bluetooth/ble5_bus.dart';
export 'src/connections/bluetooth/ble5_radio.dart';
export 'src/connections/bluetooth/ble_gatt_client.dart';
export 'src/connections/bluetooth/ble_gatt_server.dart';
export 'src/connections/bluetooth/ble_parcel.dart';
export 'src/connections/bluetooth/ble_queue_service.dart';
export 'src/connections/bluetooth/ble_reassembler.dart';
