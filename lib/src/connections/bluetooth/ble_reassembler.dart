// BLE framing limits shared by the host and the ESP32.
//
// This file used to hold two reassemblers: the scan-response continuation
// joiner and the multi-chunk broadcast-parcel ARQ. Both served the legacy
// 0x50/0x51/0x52 connectionless dialect, and no station ever parsed a byte of
// it — `on_ble` (firmware/common/xprs_app/xprs_app.c) drops any manufacturer
// subtype that is not 0x58 on its first line, and the host's chunker did not
// even carry the subtype. The host's legacy scan and chunker are gone; so are
// they. What the BLE5 lane still needs is the size router's ceiling and the
// window it measures duplicate frames against.

/// Largest payload the connectionless lane carries; above this the size router
/// in [BleService.enqueueAdvert] uses GATT point-to-point instead. Shared with
/// the ESP32 (BCAST_MAX in ble_hello.c). On a BLE5 device the real ceiling is
/// whatever the controller reports — this is the fallback and the cap the
/// router quotes when no controller answer is in yet.
const int kBleBcastMax = 300;

/// Suppress re-delivery of an identical broadcast frame for this long. A sender
/// keeps an important message on air for up to ~120 s (the ESP32's BCH_TTL_MSG)
/// so a phone whose BLE stack scans only sporadically still catches it; without
/// a dedup window longer than that air time, every re-air delivers again.
const Duration kBleBcastDedup = Duration(seconds: 130);
