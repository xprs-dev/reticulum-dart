/*
 * Pure-Dart cryptographic primitives for the Aurora Reticulum (RNS) node.
 *
 * Wire-compatible with the canonical Python reference (markqvist/Reticulum,
 * pinned to RNS 1.3.5). Every primitive here mirrors a specific reference file:
 *   - SHA-256 / truncated hashes      -> RNS/Identity.py full_hash/truncated_hash
 *   - HKDF (RFC-5869, HMAC-SHA256)    -> RNS/Cryptography/HKDF.py
 *   - AES-256-CBC + PKCS7            -> RNS/Cryptography/AES.py + PKCS7.py
 *   - Token (Fernet-like)            -> RNS/Cryptography/Token.py
 *   - X25519 ECDH / Ed25519 sign     -> RNS/Identity.py (Curve25519 keyset)
 *
 * All pure Dart, no native binaries: X25519/Ed25519 from `cryptography`,
 * SHA-256/HMAC from `crypto`, AES from `pointycastle`.
 */
import 'dart:async';
import 'dart:isolate';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as c;
import 'package:pointycastle/export.dart' as pc;

/// RNS truncated-hash length: 128 bits = 16 bytes (destination / identity hash).
const int kRnsTruncatedHashBytes = 16;

class RnsCrypto {
  static final _x25519 = c.X25519();
  static final _ed25519 = c.Ed25519();

  /// Crypto ops dispatched to the worker isolate since the last call, by op
  /// name (plus `shed`). The worker can burn a whole core under a busy hub, so
  /// this is how the host attributes that CPU — and proves any reduction.
  static Map<String, int> drainCryptoStats() =>
      _CryptoWorker.instance.drainStats();

  // ---- hashing (RNS/Identity.py) ----

  /// SHA-256 of [data] (RNS `full_hash`).
  static Uint8List fullHash(List<int> data) =>
      Uint8List.fromList(crypto.sha256.convert(data).bytes);

  /// First 16 bytes of SHA-256 (RNS `truncated_hash`).
  static Uint8List truncatedHash(List<int> data) =>
      Uint8List.sublistView(fullHash(data), 0, kRnsTruncatedHashBytes);

  static Uint8List hmacSha256(List<int> key, List<int> data) =>
      Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(data).bytes);

  /// HKDF exactly as RNS/Cryptography/HKDF.py (RFC-5869, HMAC-SHA256).
  /// PRK = HMAC(salt, ikm); T(i) = HMAC(PRK, T(i-1) || context || byte(i)),
  /// with i counting from 1 and wrapping at 256. salt defaults to 32 zero bytes,
  /// context defaults to empty.
  static Uint8List hkdf(int length, List<int> deriveFrom,
      {List<int>? salt, List<int>? context}) {
    if (length < 1) throw ArgumentError('Invalid output key length');
    if (deriveFrom.isEmpty) {
      throw ArgumentError('Cannot derive key from empty input material');
    }
    final saltBytes =
        (salt == null || salt.isEmpty) ? Uint8List(32) : salt;
    final ctx = context ?? const <int>[];
    final prk = hmacSha256(saltBytes, deriveFrom);
    final out = BytesBuilder();
    var block = <int>[];
    final blocks = (length + 31) ~/ 32;
    for (var i = 0; i < blocks; i++) {
      block = hmacSha256(prk, [...block, ...ctx, (i + 1) % 256]);
      out.add(block);
    }
    return Uint8List.sublistView(out.toBytes(), 0, length);
  }

  /// Constant-time byte comparison.
  static bool constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  // ---- AES-256-CBC + PKCS7 (RNS/Cryptography/AES.py + PKCS7.py) ----

  static Uint8List _aes256CbcRaw(
      Uint8List key, Uint8List iv, Uint8List data, bool encrypt) {
    if (key.length != 32) throw ArgumentError('AES-256 key must be 32 bytes');
    final cipher = pc.CBCBlockCipher(pc.AESEngine())
      ..init(encrypt, pc.ParametersWithIV(pc.KeyParameter(key), iv));
    final out = Uint8List(data.length);
    var off = 0;
    while (off < data.length) {
      off += cipher.processBlock(data, off, out, off);
    }
    return out;
  }

  static Uint8List pkcs7Pad(Uint8List data, [int bs = 16]) {
    final n = bs - (data.length % bs);
    final out = Uint8List(data.length + n)..setRange(0, data.length, data);
    for (var i = data.length; i < out.length; i++) {
      out[i] = n;
    }
    return out;
  }

  static Uint8List pkcs7Unpad(Uint8List data, [int bs = 16]) {
    if (data.isEmpty) throw ArgumentError('Cannot unpad empty data');
    final n = data[data.length - 1];
    if (n == 0 || n > bs || n > data.length) {
      throw ArgumentError('Invalid PKCS7 padding length $n');
    }
    return Uint8List.sublistView(data, 0, data.length - n);
  }

  // ---- X25519 (RNS Curve25519 ECDH) ----

  /// Generate an X25519 keypair, off the UI isolate. Every inbound link
  /// request makes the responder generate an EPHEMERAL keypair — live stacks
  /// caught the main isolate pegged inside this exact call under a LAN
  /// link-request flood. Falls back inline if the worker cannot start.
  static Future<({Uint8List priv, Uint8List pub})> x25519Generate(
      [Uint8List? seed]) async {
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.x25519Gen,
      a: seed != null ? Uint8List.fromList(seed) : Uint8List(0),
    );
    if (out is List && out.length == 2) {
      return (priv: out[0] as Uint8List, pub: out[1] as Uint8List);
    }
    final kp = seed != null
        ? await _x25519.newKeyPairFromSeed(seed)
        : await _x25519.newKeyPair();
    final priv = Uint8List.fromList(await kp.extractPrivateKeyBytes());
    final pub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
    return (priv: priv, pub: pub);
  }

  static Future<Uint8List> x25519PublicFromPrivate(Uint8List priv) async {
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.x25519Pub,
      a: Uint8List.fromList(priv),
    );
    if (out is Uint8List) return out;
    // Worker unavailable — fall back inline (rare path, correctness first).
    final kp = await _x25519.newKeyPairFromSeed(priv);
    return Uint8List.fromList((await kp.extractPublicKey()).bytes);
  }

  /// X25519 ECDH, off the UI isolate — one scalar multiplication per link
  /// handshake in pure Dart is far too slow to run inline under a
  /// link-request flood (live stacks caught the main isolate inside the
  /// curve math). Falls back inline if the worker cannot start.
  static Future<Uint8List> x25519Shared(
      Uint8List ourPriv, Uint8List theirPub) async {
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.x25519Shared,
      a: Uint8List.fromList(ourPriv),
      b: Uint8List.fromList(theirPub),
    );
    if (out is Uint8List) return out;
    final kp = await _x25519.newKeyPairFromSeed(ourPriv);
    final shared = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: c.SimplePublicKey(theirPub, type: c.KeyPairType.x25519),
    );
    return Uint8List.fromList(await shared.extractBytes());
  }

  // ---- Ed25519 (RNS signature keyset) ----

  static Future<({Uint8List priv, Uint8List pub})> ed25519Generate(
      [Uint8List? seed]) async {
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.edGen,
      a: seed != null ? Uint8List.fromList(seed) : Uint8List(0),
    );
    if (out is List && out.length == 2) {
      return (priv: out[0] as Uint8List, pub: out[1] as Uint8List);
    }
    final kp = seed != null
        ? await _ed25519.newKeyPairFromSeed(seed)
        : await _ed25519.newKeyPair();
    final priv = Uint8List.fromList(await kp.extractPrivateKeyBytes());
    final pub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
    return (priv: priv, pub: pub);
  }

  static Future<Uint8List> ed25519PublicFromSeed(Uint8List seed) async {
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.edPub,
      a: Uint8List.fromList(seed),
    );
    if (out is Uint8List) return out;
    final kp = await _ed25519.newKeyPairFromSeed(seed);
    return Uint8List.fromList((await kp.extractPublicKey()).bytes);
  }

  /// Sign off the UI isolate. Pure-Dart signing derives the keypair from the
  /// seed EVERY call (two point multiplications) — live stacks caught the main
  /// isolate pegged inside that derivation. The worker caches keypairs by
  /// seed, so our identity signs with one point-mul and zero main-isolate
  /// curve math. Falls back inline if the worker cannot start.
  static Future<Uint8List> ed25519Sign(
      Uint8List seed, List<int> message) async {
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.edSign,
      a: Uint8List.fromList(seed),
      b: Uint8List.fromList(message),
    );
    if (out is Uint8List) return out;
    final kp = await _ed25519.newKeyPairFromSeed(seed);
    final sig = await _ed25519.sign(message, keyPair: kp);
    return Uint8List.fromList(sig.bytes);
  }

  /// Verify off the UI isolate. Pure-Dart Ed25519 is CPU-heavy enough that a
  /// busy Reticulum hub's announce flood ANRs Flutter if verified inline — but
  /// spawning an isolate PER verification is worse: the spawn/teardown churn
  /// saturates the main isolate and an unbounded backlog of waiting futures
  /// eats the heap (observed as a multi-hour app wedge). So: ONE persistent
  /// worker isolate, request/response over ports, and a BOUNDED queue — when
  /// more than [_verifyQueueCap] verifications are already waiting, new ones
  /// are shed (returned as failed, dropping that announce), the same
  /// availability-over-completeness semantics the transport's announce budget
  /// already applies. A shed can never make a forged signature pass.
  static Future<bool> ed25519Verify(
      Uint8List pub, List<int> message, Uint8List sig) async {
    // Verifies are attacker-controlled volume: shed under backlog (fail
    // closed — the packet is dropped, a forged signature can never pass).
    final out = await _CryptoWorker.instance.request(
      _CryptoOp.edVerify,
      a: Uint8List.fromList(pub),
      b: Uint8List.fromList(message),
      c2: Uint8List.fromList(sig),
      shedUnderLoad: true,
    );
    return out == true;
  }
}

enum _CryptoOp { edVerify, edSign, edPub, x25519Shared, x25519Pub, x25519Gen, edGen }

/// One long-lived crypto isolate for every hot Curve25519 operation. Pure-Dart
/// point multiplication costs tens of ms on phone hardware; inline it and any
/// packet/link/announce flood pegs the UI isolate (observed live). Requests are
/// (id, op, args) tuples over ports; the worker caches keypairs by seed so our
/// own identity never re-derives. The pending map is bounded — beyond the cap,
/// sheddable ops (inbound verifies) fail closed, while our OWN operations
/// (signs, ECDH — self-limited rates) still queue.
class _CryptoWorker {
  _CryptoWorker._();
  static final _CryptoWorker instance = _CryptoWorker._();

  static const int _shedCap = 64; // pending beyond this → shed verifies
  static const int _hardCap = 512; // absolute pending bound

  SendPort? _toWorker;
  Future<void>? _starting;
  final Map<int, Completer<Object?>> _pending = {};
  int _seq = 0;
  int shed = 0; // dropped-op count, for diagnostics

  /// Ops dispatched since the last [drainStats], by op name. The worker is a
  /// whole CPU core's worth of curve math under a busy hub — knowing WHICH op
  /// dominates (inbound verifies vs our own signs vs link ECDH) is what tells
  /// you whether to shed harder or announce less. Read by the host's perf log.
  final Map<String, int> _opCounts = {};

  Map<String, int> drainStats() {
    final out = Map<String, int>.from(_opCounts);
    _opCounts.clear();
    if (shed > 0) {
      out['shed'] = shed;
      shed = 0;
    }
    return out;
  }

  /// Run [op] on the worker. Returns null when the op was shed or the worker
  /// is unavailable — callers treat that as failure (or fall back inline for
  /// rare non-hot paths).
  Future<Object?> request(
    _CryptoOp op, {
    required Uint8List a,
    Uint8List? b,
    Uint8List? c2,
    bool shedUnderLoad = false,
  }) async {
    final cap = shedUnderLoad ? _shedCap : _hardCap;
    if (_pending.length >= cap) {
      shed++;
      return null;
    }
    _opCounts[op.name] = (_opCounts[op.name] ?? 0) + 1;
    if (_toWorker == null) {
      _starting ??= _spawn();
      try {
        await _starting;
      } catch (_) {
        _starting = null;
        return null;
      }
    }
    final port = _toWorker;
    if (port == null) return null;
    final id = _seq++;
    final done = Completer<Object?>();
    _pending[id] = done;
    port.send([id, op.index, a, b, c2]);
    return done.future;
  }

  Future<void> _spawn() async {
    final fromWorker = ReceivePort();
    final ready = Completer<void>();
    fromWorker.listen((msg) {
      if (msg is SendPort) {
        _toWorker = msg;
        if (!ready.isCompleted) ready.complete();
        return;
      }
      if (msg is List && msg.length == 2) {
        _pending.remove(msg[0] as int)?.complete(msg[1]);
      }
    });
    try {
      final iso = await Isolate.spawn(
        _cryptoWorkerMain,
        fromWorker.sendPort,
        debugName: 'rns-crypto',
      );
      // If the worker dies, fail the backlog and allow a lazy respawn.
      final exit = ReceivePort();
      iso.addOnExitListener(exit.sendPort);
      exit.listen((_) {
        exit.close();
        fromWorker.close();
        _toWorker = null;
        _starting = null;
        for (final c in _pending.values) {
          if (!c.isCompleted) c.complete(null);
        }
        _pending.clear();
      });
    } catch (e) {
      fromWorker.close();
      if (!ready.isCompleted) ready.completeError(e);
      rethrow;
    }
    return ready.future;
  }
}

Future<void> _cryptoWorkerMain(SendPort toMain) async {
  final ed = c.Ed25519();
  final x = c.X25519();
  // Keypair caches keyed by seed hex — our identity signs constantly with the
  // SAME seed; deriving the keypair once turns two point-muls per sign into
  // one. Bounded: an RNS node touches a handful of own keys, never thousands.
  final edKeys = <String, c.SimpleKeyPair>{};
  final xKeys = <String, c.SimpleKeyPair>{};
  const cacheCap = 64;
  String hex(Uint8List b) =>
      b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
  Future<c.SimpleKeyPair> edFor(Uint8List seed) async {
    final k = hex(seed);
    final hit = edKeys[k];
    if (hit != null) return hit;
    if (edKeys.length >= cacheCap) edKeys.remove(edKeys.keys.first);
    return edKeys[k] = await ed.newKeyPairFromSeed(seed);
  }

  Future<c.SimpleKeyPair> xFor(Uint8List seed) async {
    final k = hex(seed);
    final hit = xKeys[k];
    if (hit != null) return hit;
    if (xKeys.length >= cacheCap) xKeys.remove(xKeys.keys.first);
    return xKeys[k] = await x.newKeyPairFromSeed(seed);
  }

  final inbox = ReceivePort();
  toMain.send(inbox.sendPort);
  await for (final msg in inbox) {
    if (msg is! List || msg.length != 5) continue;
    final id = msg[0] as int;
    final op = _CryptoOp.values[msg[1] as int];
    final a = msg[2] as Uint8List;
    final b = msg[3] as Uint8List?;
    final c2 = msg[4] as Uint8List?;
    Object? out;
    try {
      switch (op) {
        case _CryptoOp.edVerify:
          out = await ed.verify(
            b!,
            signature: c.Signature(
              c2!,
              publicKey: c.SimplePublicKey(a, type: c.KeyPairType.ed25519),
            ),
          );
        case _CryptoOp.edSign:
          final kp = await edFor(a);
          final sig = await ed.sign(b!, keyPair: kp);
          out = Uint8List.fromList(sig.bytes);
        case _CryptoOp.edPub:
          final kp = await edFor(a);
          out = Uint8List.fromList((await kp.extractPublicKey()).bytes);
        case _CryptoOp.x25519Shared:
          final kp = await xFor(a);
          final shared = await x.sharedSecretKey(
            keyPair: kp,
            remotePublicKey:
                c.SimplePublicKey(b!, type: c.KeyPairType.x25519),
          );
          out = Uint8List.fromList(await shared.extractBytes());
        case _CryptoOp.x25519Pub:
          final kp = await xFor(a);
          out = Uint8List.fromList((await kp.extractPublicKey()).bytes);
        case _CryptoOp.x25519Gen:
          final kp = a.isEmpty ? await x.newKeyPair() : await x.newKeyPairFromSeed(a);
          out = [
            Uint8List.fromList(await kp.extractPrivateKeyBytes()),
            Uint8List.fromList((await kp.extractPublicKey()).bytes),
          ];
        case _CryptoOp.edGen:
          final kp =
              a.isEmpty ? await ed.newKeyPair() : await ed.newKeyPairFromSeed(a);
          out = [
            Uint8List.fromList(await kp.extractPrivateKeyBytes()),
            Uint8List.fromList((await kp.extractPublicKey()).bytes),
          ];
      }
    } catch (_) {
      out = op == _CryptoOp.edVerify ? false : null;
    }
    toMain.send([id, out]);
  }
}

/// Slightly-modified Fernet token used by RNS (RNS/Cryptography/Token.py).
/// AES-256-CBC + HMAC-SHA256, no version/timestamp fields. The 64-byte key is
/// split into a 32-byte signing key and a 32-byte encryption key.
class RnsToken {
  final Uint8List _signingKey;
  final Uint8List _encryptionKey;

  RnsToken(Uint8List key)
      : assert(key.length == 64, 'RNS token key must be 64 bytes'),
        _signingKey = Uint8List.sublistView(key, 0, 32),
        _encryptionKey = Uint8List.sublistView(key, 32, 64);

  /// token = iv(16) + AES256CBC(PKCS7(plaintext)) + HMAC_SHA256(signing, iv+ct).
  /// [iv] is for deterministic testing only; production passes null (random).
  Uint8List encrypt(Uint8List plaintext, {Uint8List? iv}) {
    final theIv = iv ?? _randomBytes(16);
    if (theIv.length != 16) throw ArgumentError('IV must be 16 bytes');
    final ct = RnsCrypto._aes256CbcRaw(
        _encryptionKey, theIv, RnsCrypto.pkcs7Pad(plaintext), true);
    final signed = Uint8List(16 + ct.length)
      ..setRange(0, 16, theIv)
      ..setRange(16, 16 + ct.length, ct);
    final mac = RnsCrypto.hmacSha256(_signingKey, signed);
    return Uint8List(signed.length + 32)
      ..setRange(0, signed.length, signed)
      ..setRange(signed.length, signed.length + 32, mac);
  }

  bool verifyHmac(Uint8List token) {
    if (token.length <= 32) return false;
    final received = Uint8List.sublistView(token, token.length - 32);
    final expected = RnsCrypto.hmacSha256(
        _signingKey, Uint8List.sublistView(token, 0, token.length - 32));
    return RnsCrypto.constantTimeEquals(received, expected);
  }

  Uint8List decrypt(Uint8List token) {
    if (!verifyHmac(token)) throw ArgumentError('Token HMAC was invalid');
    final iv = Uint8List.sublistView(token, 0, 16);
    final ct = Uint8List.sublistView(token, 16, token.length - 32);
    return RnsCrypto.pkcs7Unpad(
        RnsCrypto._aes256CbcRaw(_encryptionKey, iv, ct, false));
  }
}

final math.Random _secureRng = math.Random.secure();

Uint8List _randomBytes(int n) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = _secureRng.nextInt(256);
  }
  return out;
}
