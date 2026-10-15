// XPRS.md 6.1.3's second signature form needs a standard BIP-340 signer and
// verifier. Checked against BIP-340's own test vectors.
import 'dart:typed_data';

import 'package:reticulum/src/util/xprs_crypto.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List unhex(String h) => Uint8List.fromList(
    [for (var i = 0; i < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)]);
String hex(Uint8List b) =>
    b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();

void main() {
  // bip-0340/test-vectors.csv, index 0 and 1.
  final zeros = Uint8List(32);

  test('signs BIP-340 vector 0 byte for byte', () {
    final sig = XprsCrypto.bip340Sign(zeros, BigInt.from(3), aux: zeros);
    expect(hex(sig).toUpperCase(),
        'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215'
        '25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0');
    expect(hex(XprsCrypto.publicKeyXOnly(BigInt.from(3))).toUpperCase(),
        'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
  });

  test('verifies BIP-340 vectors 0 and 1, and refuses a flipped bit', () {
    final pub0 = unhex('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9');
    final sig0 = unhex('E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215'
        '25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0');
    expect(XprsCrypto.bip340Verify(zeros, sig0, pub0), isTrue);
    final pub1 = unhex('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659');
    final msg1 = unhex('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89');
    final sig1 = unhex('6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341'
        '8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A');
    expect(XprsCrypto.bip340Verify(msg1, sig1, pub1), isTrue);
    final bad = Uint8List.fromList(sig1)..[40] ^= 1;
    expect(XprsCrypto.bip340Verify(msg1, bad, pub1), isFalse);
    expect(XprsCrypto.bip340Verify(zeros, sig0, pub1), isFalse,
        reason: 'the wrong key');
    expect(XprsCrypto.bip340Verify(zeros, sig0.sublist(0, 63), pub0), isFalse);
  });

  test('a signature it makes verifies, with fresh aux', () {
    final d = BigInt.parse('1234567890abcdef1234567890abcdef', radix: 16);
    final m = Uint8List.fromList(List.generate(32, (i) => i * 7));
    final sig = XprsCrypto.bip340Sign(m, d);
    expect(XprsCrypto.bip340Verify(m, sig, XprsCrypto.publicKeyXOnly(d)), isTrue);
  });
}
