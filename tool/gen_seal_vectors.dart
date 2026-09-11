// Interop vectors for the ESP32's sealed-command opener (XPRS.md 6.2, 11.4,
// 11.10).
//
// A phone seals a password to a station with XprsCrypto.encryptFor, and the
// station, in C, has to open it. The IV is random, so the C side cannot
// reproduce these bytes; it must OPEN them, which checks the ECDH, the use of
// the bare X coordinate as the key, AES-256-CBC, the padding and the
// base64url all at once.
//
//   dart run tool/gen_seal_vectors.dart
//
// and paste the output into firmware/common/xprs_sig/test_xprsseal_host.c.
import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:reticulum/src/util/xprs_crypto.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List xonly(BigInt d) {
  final p = (ECCurve_secp256k1().G * d)!;
  final x = p.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0');
  return Uint8List.fromList(List.generate(
      32, (i) => int.parse(x.substring(i * 2, i * 2 + 2), radix: 16)));
}

String b64u(List<int> b) => base64Url.encode(b).replaceAll('=', '');

void main() {
  // The phone (an owner) and the station. Toy keys: never seal with these.
  final phone = BigInt.parse(
      '1111111111111111111111111111111111111111111111111111111111111111',
      radix: 16);
  final station = BigInt.parse(
      '2222222222222222222222222222222222222222222222222222222222222222',
      radix: 16);
  final phoneX = xonly(phone), stationX = xonly(station);
  print('phone_priv   ${phone.toRadixString(16).padLeft(64, '0')}');
  print('phone_x      ${hex(phoneX)}');
  print('station_priv ${station.toRadixString(16).padLeft(64, '0')}');
  print('station_x    ${hex(stationX)}');
  print('shared       ${hex(XprsCrypto.ecdhShared(phone, stationX)!)}');

  final plains = [
    'cmd:set\nssid:Casa do Mar\npass:sardinha na brasa 2026',
    'cmd:set\npass:${'p' * 31}${'Q' * 32}',
    'cmd:set\nnsec:nsec1${'q' * 58}',
  ];
  for (final p in plains) {
    final blob = XprsCrypto.encryptFor(phone, stationX,
        Uint8List.fromList(utf8.encode(p)))!;
    final back = XprsCrypto.decryptFrom(station, phoneX, blob);
    print('plain        ${jsonEncode(p)}');
    print('x            ${b64u(blob)}');
    print('selfcheck    ${back != null && utf8.decode(back) == p}');
  }
}
