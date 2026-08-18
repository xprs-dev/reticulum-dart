// Interop vectors for the ESP32 RNS codec (see the xprs-esp32 repository).
// Deterministic on purpose: fixed seeds and a fixed IV, so the C implementation
// must reproduce these exact bytes or it is not speaking Reticulum.
import 'dart:convert';
import 'dart:typed_data';
import 'package:reticulum/src/services/reticulum/rns_crypto.dart';
import 'package:reticulum/src/services/reticulum/rns_identity.dart';

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Future<void> main() async {
  // private key = x25519_prv(32) + ed25519_prv(32), fixed for reproducibility
  final prv = Uint8List.fromList(
      List.generate(32, (i) => i + 1) + List.generate(32, (i) => 0x40 + i));
  final id = await RnsIdentity.fromPrivateKey(prv);
  print('identity_prv   ${hex(prv)}');
  print('identity_pub   ${hex(id.pubBytes)}');
  print('identity_hash  ${hex(id.hash)}');

  final prk = RnsCrypto.hkdf(64, utf8.encode('shared-secret'), salt: id.hash);
  print('hkdf64         ${hex(prk)}');

  final ephSeed = Uint8List.fromList(List.generate(32, (i) => 0xA0 + i));
  final iv = Uint8List.fromList(List.generate(16, (i) => 0x10 + i));
  final pt = utf8.encode('t:warning f:X3RLY7 kind:fire sev:danger');
  final ct = await id.encrypt(Uint8List.fromList(pt), ephemeralSeed: ephSeed, iv: iv);
  print('plaintext      ${hex(pt)}');
  print('ciphertext     ${hex(ct)}');
}
