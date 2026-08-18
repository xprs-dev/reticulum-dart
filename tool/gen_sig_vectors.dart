// Interop vectors for the ESP32 XPRS signer.
//
// The signature is randomised (fresh aux per call), so the C side cannot
// reproduce these bytes — it must VERIFY them, which is the stronger property
// anyway: a verifier that agrees has the curve, the tagged hashes and the
// truncated challenge all right.
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:reticulum/src/util/xprs_crypto.dart';

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final d = BigInt.parse(
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      radix: 16);
  final text = 't:service f:X3JS7Y serve:index,history,mailbox count:32';
  final digest = Uint8List.fromList(sha256.convert(utf8.encode(text)).bytes);

  // x-only public key for d, with the BIP-340 even-y convention
  final curve = ECCurve_secp256k1();
  var dp = d;
  var p = (curve.G * d)!;
  if (p.y!.toBigInteger()!.isOdd) { dp = curve.n - d; p = (curve.G * dp)!; }
  final px = p.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0');

  final sig = XprsCrypto.sign(digest, d);
  print('text     $text');
  print('scalar   ${d.toRadixString(16).padLeft(64, '0')}');
  print('digest   ${hex(digest)}');
  print('pubx     $px');
  print('sig      ${hex(sig)}');
  print('sig_b85  ${XprsCrypto.b85encode(sig)}');
  print('selfcheck ${XprsCrypto.verify(digest, sig, Uint8List.fromList(
      List.generate(32, (i) => int.parse(px.substring(i * 2, i * 2 + 2), radix: 16))))}');
  final known = Uint8List.fromList([0,1,2,3, 250,251,252,253]);
  print('b85in    ${hex(known)}');
  print('b85out   ${XprsCrypto.b85encode(known)}');
}
