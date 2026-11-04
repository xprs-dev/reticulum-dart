/// BLE transport for the `reticulum` package: BLE5 extended-advertising bus
/// and radio, GATT client/server, and the parcel queue.
///
/// Kept apart from `reticulum` because it needs Flutter platform plugins;
/// everything else in the stack is plain Dart.
library;

export 'src/ble5_bus.dart';
export 'src/ble5_radio.dart';
export 'src/ble_gatt_client.dart';
export 'src/ble_gatt_server.dart';
export 'src/ble_queue_service.dart';
