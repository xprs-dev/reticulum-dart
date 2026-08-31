/*
 * Copyright (c) XPRS
 * License: Apache-2.0
 *
 * NOSTR Key Generator - Uses proper secp256k1 cryptography
 *
 * Vendored from XPRS/lib/util/nostr_key_generator.dart — keep in
 * sync manually until a shared package lands.
 */

import 'nostr_crypto.dart';

/// Generates NOSTR key pairs (npub/nsec) using secp256k1
class NostrKeyGenerator {
  /// Generate a new key pair with proper secp256k1 keys
  ///
  /// [callsignLength] is how many characters of the key the holder chooses to
  /// show, 2 to 5 (spec section 3). Four is the default and what every
  /// callsign in the field is today.
  static NostrKeys generateKeyPair(
      {int callsignLength = NostrCrypto.kDefaultCallsignLength}) {
    final keyPair = NostrCrypto.generateKeyPair();
    return NostrKeys(
      npub: keyPair.npub,
      nsec: keyPair.nsec,
      callsign: keyPair.callsignOfLength(length: callsignLength),
    );
  }

  /// Derive user/operator callsign from npub
  /// Format: X1 + the first [length] characters after 'npub1'
  static String deriveCallsign(String npub,
      {int length = NostrCrypto.kDefaultCallsignLength}) {
    return _deriveCallsignFromNpub(npub, 'X1', length);
  }

  /// Derive station callsign from npub
  /// Format: X3 + the first [length] characters after 'npub1'
  static String deriveStationCallsign(String npub,
      {int length = NostrCrypto.kDefaultCallsignLength}) {
    return _deriveCallsignFromNpub(npub, 'X3', length);
  }

  /// Derive a movable-station callsign (ship, aircraft, bus, car).
  ///
  /// Format: X2 + the first [length] characters after 'npub1'
  /// (XPRS.md section 3: X2 moves, X3 stays where it is).
  static String deriveMobileCallsign(String npub,
      {int length = NostrCrypto.kDefaultCallsignLength}) {
    return _deriveCallsignFromNpub(npub, 'X2', length);
  }

  /// Derive callsign from npub with given prefix
  /// Takes the first [length] characters after 'npub1' and uppercases them
  static String _deriveCallsignFromNpub(
      String npub, String prefix, int length) {
    if (length < NostrCrypto.kMinCallsignLength ||
        length > NostrCrypto.kMaxCallsignLength) {
      throw ArgumentError.value(length, 'length',
          'callsign length must be ${NostrCrypto.kMinCallsignLength}..'
              '${NostrCrypto.kMaxCallsignLength}');
    }
    if (npub.length < 5 + length || !npub.toLowerCase().startsWith('npub1')) {
      throw ArgumentError('Invalid npub format');
    }

    // Extract the first `length` characters after 'npub1' and uppercase
    final suffix = npub.substring(5, 5 + length).toUpperCase();

    return '$prefix$suffix';
  }

  /// Validate npub format (must be proper bech32-encoded public key)
  static bool isValidNpub(String npub) {
    try {
      if (!npub.startsWith('npub1')) return false;
      NostrCrypto.decodeNpub(npub);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Validate nsec format (must be proper bech32-encoded private key)
  static bool isValidNsec(String nsec) {
    try {
      if (!nsec.startsWith('nsec1')) return false;
      NostrCrypto.decodeNsec(nsec);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Get public key hex from npub (returns null if invalid)
  static String? getPublicKeyHex(String npub) {
    try {
      return NostrCrypto.decodeNpub(npub);
    } catch (e) {
      return null;
    }
  }

  /// Get private key hex from nsec (returns null if invalid)
  static String? getPrivateKeyHex(String nsec) {
    try {
      return NostrCrypto.decodeNsec(nsec);
    } catch (e) {
      return null;
    }
  }

  /// Derive npub from nsec
  static String? derivePublicKey(String nsec) {
    try {
      final privateKeyHex = NostrCrypto.decodeNsec(nsec);
      final publicKeyHex = NostrCrypto.derivePublicKey(privateKeyHex);
      return NostrCrypto.encodeNpub(publicKeyHex);
    } catch (e) {
      return null;
    }
  }
}

/// NOSTR key pair with callsign
class NostrKeys {
  final String npub; // Public key (bech32 encoded)
  final String nsec; // Private key (bech32 encoded, secret!)
  final String callsign; // Derived callsign

  NostrKeys({
    required this.npub,
    required this.nsec,
    String? callsign,
  }) : callsign = callsign ?? NostrKeyGenerator.deriveCallsign(npub);

  /// Create a station key pair with X3 callsign prefix
  factory NostrKeys.forRelay() {
    final keys = NostrKeyGenerator.generateKeyPair();
    return NostrKeys(
      npub: keys.npub,
      nsec: keys.nsec,
      callsign: NostrKeyGenerator.deriveStationCallsign(keys.npub),
    );
  }

  /// Get the hex-encoded public key
  String? get publicKeyHex => NostrKeyGenerator.getPublicKeyHex(npub);

  /// Get the hex-encoded private key (use with caution!)
  String? get privateKeyHex => NostrKeyGenerator.getPrivateKeyHex(nsec);

  Map<String, dynamic> toJson() {
    return {
      'npub': npub,
      'nsec': nsec,
      'callsign': callsign,
      'created': DateTime.now().millisecondsSinceEpoch,
    };
  }

  factory NostrKeys.fromJson(Map<String, dynamic> json) {
    return NostrKeys(
      npub: json['npub'] as String,
      nsec: json['nsec'] as String,
      callsign: json['callsign'] as String?,
    );
  }
}
