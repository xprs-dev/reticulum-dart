/*
 * The BLE5 advert bus's data types: subtypes and a received frame. Plain
 * data, so the core (which has no Flutter) can name them; the bus itself, a
 * platform channel, is in packages/reticulum_ble.
 */
import 'dart:typed_data';

/// Manufacturer-data subtypes carried under company id 0xFFFF, marker 0x3E.
class Ble5Subtype {
  static const int rns = 0x55; // Reticulum packet
  // A Reticulum packet too big for one extended advert, split across several.
  // Its own subtype so a chunk is never mistaken for a whole packet (and never
  // lands in the APRS reassembler, which speaks a different framing).
  static const int rnsChunk = 0x56; // Reticulum packet fragment
  static const int aprs = 0x41; // APRS broadcast parcel ('A')
  static const int presence = 0x47; // GATT presence beacon ('G'): callsign
  static const int mesh = 0x4D; // street-mesh route beacon ('M'), doc/mesh.md
  static const int wfd = 0x57; // WiFi-Direct negotiation ('W'): ADVERT/REQ/OFFER
  // XPRS text packets ('X'), docs/XPRS.md — the discovery beacon and carried
  // mail. Its own subtype so a receiver never has to sniff a frame to tell XPRS
  // from the compact `FROM\x1FTO\x1Ftext` the chat wapp and the ESP32 still put
  // on 0x41, and so those two ignore what they cannot read instead of trying.
  static const int xprs = 0x58;
}

/// One inbound connectionless frame, already demuxed to a single subtype.
class Ble5Frame {
  final String addr; // advertiser address (rotating random MAC)
  final int rssi;
  final Uint8List data; // payload after marker+subtype
  const Ble5Frame(this.addr, this.rssi, this.data);
}
